#!/usr/bin/env python
#
# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Module with code to handle X509 certificates.

Classes:

  X509Certificate: class to load, hold, interpet a X509Certificate

Functions:

  LoadCertificateFromBase64: load a certificate from base64 string
  LoadCertificateFromPEMFormat: load a certificate from PEM format (e.g.
    OpenSSL command line tools output)
"""





import base64
import datetime
import hashlib
import re
import time
import pyasn1
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
import pyasn1.error
from pyasn1.type import univ
import pyasn1.type.useful

from simian.auth import tlslite_bridge


# OIDs as a dict, for quick lookup of the OID
OID_NAME = {
    (2, 5, 4, 3): 'CN',
    (2, 5, 4, 6): 'C',
    (2, 5, 4, 7): 'L',
    (2, 5, 4, 8): 'ST',
    (2, 5, 4, 10): 'O',
    (2, 5, 4, 11): 'OU',
    (1, 2, 840, 113549, 1, 9, 1): 'emailAddress',
    (0, 9, 2342, 19200300, 100, 1, 25): 'DC',
}

# OIDs as a dict, for quick lookup of the string, e.g. 'CN'
OID_ID = {}
for k, v in OID_NAME.iteritems():
  OID_ID[v] = k
OID_ID['domainComponent'] = OID_ID['DC']  # alias


# OID SHA1 Hash with RSA Encryption
# http://www.alvestrand.no/objectid/1.2.840.11359.html
OID_SHA1_WITH_RSA_ENC = (1, 2, 840, 113549, 1, 1, 5)
# OID SHA256 Hash with RSA Encryption
# http://www.alvestrand.no/objectid/1.2.840.113549.1.1.11.html
OID_SHA256_WITH_RSA_ENC = (1, 2, 840, 113549, 1, 1, 11)

# Microsoft specific OIDs
# http://support.microsoft.com/kb/287547
OID_MS_NT_PRINCIPAL_NAME = (1, 3, 6, 1, 4, 1, 311, 20, 2, 3)

# X509V3 extensions: Basic Constraints
# http://www.alvestrand.no/objectid/2.5.29.19.html
OID_X509V3_BASIC_CONSTRAINTS = (2, 5, 29, 19)

# X509V3 extensions: Key Usage
# http://www.alvestrand.no/objectid/2.5.29.15.html
OID_X509V3_KEY_USAGE = (2, 5, 29, 15)
X509V3_KEY_USAGE_BIT_FIELDS = (
    'digitalSignature',
    'nonRepudiation',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'CRLSign',
    'encipherOnly',
    'decipherOnly',
)

# X509V3 extensions: Subject Alternative Name
# http://www.alvestrand.no/objectid/2.5.29.17.html
OID_X509V3_SUBJECT_ALT_NAME = (2, 5, 29, 17)


# Certificate versions that X509Certificate can load
X509_CERT_VERSION_3 = 0x2


# Regex for valid, standard base64 characters. (i.e. not websafe)
BASE64_RE = re.compile(r'^[0-9A-Za-z/+=]+$')


# Constants used for RFC4514 attribute_value -> str escaping
SPACE = str(u'\u0020')
NULL = '\x00'
RFC4514_ESCAPED_CHARS = frozenset(('"', '+', ',', ';', '<', '>', '\\', NULL))


class Error(Exception):
  """Base Error."""


class CertificateError(Error):
  """Certificate Error."""


class FormatError(Error):
  """Format error."""


class CertificateValueError(CertificateError):
  """Error in a certificate value."""


class CertificateParseError(CertificateError):
  """Certificate cannot be parsed, an error in its structure."""


class CertificateFormatError(CertificateError, FormatError):
  """Certificate Format Error."""


class PEMFormatError(FormatError):
  """PEM Format Error."""


class HeaderMissingPEMFormatError(PEMFormatError):
  """Header is missing PEM Format Error."""


class FooterMissingPEMFormatError(PEMFormatError):
  """Footer is missing PEM Format Error."""


class CertificateASN1FormatError(CertificateFormatError):
  """Certificate ASN1 Format Error."""


class CertificatePEMFormatError(CertificateFormatError, PEMFormatError):
  """Certificate PEM Format Error."""


class RSAKeyPEMFormatError(PEMFormatError):
  """RSA Key PEM Format Error."""


class RSAPrivateKeyPEMFormatError(RSAKeyPEMFormatError):
  """RSA Private Key PEM Format Error."""


class BaseDataObject(object):
  """Object which can auto-generate its own Get* methods."""

  def _GetDataDict(self):
    """Returns the dictionary which holds instance data."""
    raise NotImplementedError

  @classmethod
  def CreateGetMethod(cls, name, key, setattr_=None):
    """Create a get method for a key which returns its value.

    Args:
      name: str, name for the method, e.g. "Foo"
      key: str, key in dict to retrieve, e.g. "foo"
      setattr_: function, optional, used to set attribute on class
    """
    if setattr_ is None:
      setattr_ = setattr
    setattr_(cls, 'Get%s' % name, lambda self: self._GetDataDict()[key])


class X509Certificate(BaseDataObject):
  """X509 Certificate class."""

  SIGNATURE_ALGORITHMS = [OID_SHA1_WITH_RSA_ENC, OID_SHA256_WITH_RSA_ENC]
  TIMESTAMP_FMT = '%y%m%d%H%M%SZ'

  def __init__(self):
    """Init."""
    self.Reset()
    self._required_issuer = None

  def Reset(self):
    """Reset certificate contents."""
    self._cert = {
        'serial_num': None,
        'issuer': None,
        'subject': None,
        'valid_notbefore': None,
        'valid_notafter': None,
        'fields_data': None,
        'sig_data': None,
        'sig_algorithm': None,
        'entire_cert_data': None,
        'public_key': None,
        'may_act_as_ca': None,
        'key_usage': None,
        'subject_alt_name': None,
    }

  def _GetDataDict(self):
    return self._cert

  BaseDataObject.CreateGetMethod('Issuer', 'issuer')
  BaseDataObject.CreateGetMethod('Subject', 'subject')
  BaseDataObject.CreateGetMethod('DatetimeNotValidBefore', 'valid_notbefore')
  BaseDataObject.CreateGetMethod('DatetimeNotValidAfter', 'valid_notafter')
  BaseDataObject.CreateGetMethod('FieldsData', 'fields_data')
  BaseDataObject.CreateGetMethod('SignatureData', 'sig_data')
  BaseDataObject.CreateGetMethod('SignatureAlgorithm', 'sig_algorithm')
  BaseDataObject.CreateGetMethod('SerialNumber', 'serial_num')
  BaseDataObject.CreateGetMethod('EntireCertData', 'entire_cert_data')
  BaseDataObject.CreateGetMethod('PublicKey', 'public_key')
  BaseDataObject.CreateGetMethod('MayActAsCA', 'may_act_as_ca')
  BaseDataObject.CreateGetMethod('KeyUsage', 'key_usage')
  BaseDataObject.CreateGetMethod('SubjectAltName', 'subject_alt_name')

  def _CertTimestampToDatetime(self, ts):
    """Convert a timestamp from a x509 cert into a Python datetime.

    Args:
      ts: str, timestamp like yymmddhhmmssZ where Z is always present
          denoting zulu time
    Returns:
      datetime object with no tzinfo class, but values in UTC
    Raises:
      CertificateValueError: error in a value in the certificate
    """
    try:
      t = time.strptime(str(ts), self.TIMESTAMP_FMT)
    except ValueError, e:
      raise CertificateValueError('Timestamp %s: %s' % (ts, str(e)))

    t = list(t[:6])    # y, m, d, hh, mm, ss
    t.append(0)        # ms
    # note we do not append a timezone.  assume UTC.
    d = datetime.datetime(*t)
    return d

  def _FindOctetStrings(self, values):
    """Filters a list to contain only OctetString type values.

    Args:
      values: A list that should contain OctetString(s).
    Returns:
      list of der_encoder.univ.OctetString
    """
    return [x for x in values if isinstance(x, univ.OctetString)]

  def _GetV3ExtensionFieldsFromSequence(self, seq):
    """Get X509 V3 extension fields from a sequence.

    Args:
      seq: pyasn1.type.univ.Sequence
    Returns:
      dict containing these keys if present in input sequence = {
        'key_usage': tuple of X509V3_KEY_USAGE_BIT_FIELDS items,
        'may_act_as_ca': bool,
        'subject_alt_name': str,
      }
    Raises:
      CertificateParseError: the certificate isn't constructed
        as expected way and cannot be parsed
      CertificateValueError: error in a value in the certificate
    """
    output = {}
    cert_key_usage = []

    for i in xrange(len(seq)):
      oid, values = seq[i][0], seq[i][1:]

      if oid == OID_X509V3_BASIC_CONSTRAINTS:
        # NOTE(user):
        # this doesn't seem to be formed the way the RFC describes.
        # there's a dangling extra boolean in the beginning of the
        # sequence, or I'm not understanding the RFC.  also, the
        # sequence itself is not readily available, rather it's DER-encoded
        # in an OctetString.
        #
        # consider the following real-world examples I've sampled:
        #
        # where basicConstraint CA:TRUE     CASE 1
        # generated by openssl -req:
        # ( OID,
        #   OctetString (
        #     encapsulated Sequence( Boolean True )
        # )
        #
        # where basicConstraint CA:FALSE    CASE 2
        # generated by puppet:
        # ( OID,
        #   CA = True, OctetString (
        #     encapsulated Sequence ( empty )
        # )
        #
        # where basicConstraint CA:TRUE     CASE 3
        # CA cert generated by puppet:
        # (
        #   OID,
        #   CA = True, OctetString (
        #     encapsulated Sequence ( Boolean = True )
        # )

        octet_strings = self._FindOctetStrings(values)
        if 1 < len(values) > 2:
          raise CertificateParseError('X509V3 Multiple CA/Paths')
        encaps_seq = der_decoder.decode(octet_strings[0])

        if len(encaps_seq):  # not case 2?
          if len(encaps_seq[1]):
            raise CertificateParseError(
                'X509V3 pathLenConstraint unsupported')
          # NOTE(user): The RFC and real world seem to agree here.
          # The lack of a value, not the existence of a False value,
          # is how one determines that the cert is not a CA cert.
          # So just look for True to confirm.
          if True in encaps_seq[0]:  # case 1, 3
            output['may_act_as_ca'] = True

      elif oid == OID_X509V3_KEY_USAGE:
        octet_strings = self._FindOctetStrings(values)
        # NOTE(user):
        # unbelievably this is a BitString inside of a OctetString.
        # quick sanity check to look for ASN1 type field:
        if octet_strings[0][0] != '\x03':  # ASN1 type for BitString
          raise CertificateParseError('X509V3 Key Usage encoding')

        encaps_bitstr = der_decoder.decode(octet_strings[0])[0]
        n = 0
        while n < len(encaps_bitstr):
          if encaps_bitstr[n]:
            cert_key_usage.append(X509V3_KEY_USAGE_BIT_FIELDS[n])
          n += 1

      elif oid == OID_X509V3_SUBJECT_ALT_NAME:
        octet_strings = self._FindOctetStrings(values)
        # NOTE(user): this is a Sequence inside an OctetString
        # However this field is not used a lot at Google or externally
        # so it is not well tested.
        #
        # It is suspected that this code is brittle at the point of calling
        # the DER decoder. The structure looks like this, ASN1-parsed:
        #
        #  0   52: SEQUENCE {
        #  2   23:   [2] 'puppethosta.example.com'
        # 27    6:   [2] 'puppet'
        # 35   17:   [2] 'pupha.example.com'
        #        :   }
        #
        # The [2] is the tag number which is an integer, which causes
        # decoding to fail because the values are strings.
        #
        # Special code will be required to handle this field properly.

        if octet_strings[0][0] != '\x30':   # ASN1 type for Sequence
          raise CertificateParseError('X509V3 Subject Alt Name encoding')

        encaps_seq = der_decoder.decode(octet_strings[0])[0]
        if not encaps_seq:
          continue

        if encaps_seq[0] == OID_MS_NT_PRINCIPAL_NAME:
          # NOTE(user): the following name X_MS_*= is not a
          # standard string.
          output['subject_alt_name'] = (
              'X_MS_NT_Principal_Name=%s' % encaps_seq[1])
        else:
          raise CertificateParseError(
              'X509V3 SubjectAltName Unknown OID %s' % str(encaps_seq[0]))

    cert_key_usage = tuple(cert_key_usage)
    if cert_key_usage:
      output['key_usage'] = cert_key_usage
    return output

  def _AttributeValueToString(self, value):
    """Transform an AttributeValue to a String, escaping if needed.

    Follows RFC4514 section 2.4.

    Args:
      value: string, like "Foo" from "OU=Foo"
    Returns:
      str, a new str if escaped, otherwise the same str.
    """
    value = str(value)  # pyasn1 PrintableString -> str

    # using a regex to sub() leads to problems when adjacent target chars
    # lead to overlapping matches. do this by hand.
    tmp = []
    i = 0
    while i < len(value):
      if value[i] in RFC4514_ESCAPED_CHARS:
        if i == 0 or value[i - 1] != '\\':
          if value[i] == NULL:
            tmp.append('\\00')
          else:
            tmp.append('\\%s' % value[i])
      else:
        tmp.append(value[i])
      i += 1
    value = ''.join(tmp)

    if value.startswith(SPACE):  # string may not start with unescaped space
      value = '\\' + value
    elif value.startswith('#'):  # string may not start with unescaped #
      value = '\\' + value
    if value.endswith(SPACE):    # string may not end with unprotected space
      value = value[0:-1] + '\\' + SPACE

    return value

  def _AssembleDNSequence(self, seq):
    """Assemble multiple DN fields into a string output.

    Args:
      seq: pyasn1.type.univ.Sequence, structured like =
        (
          ( (oid,value), ),
          ( (oid,value), ),
        )
    Returns:
      str like 'OU=Foo,C=Bar'
    Raises:
      CertificateParseError: the sequence structured is unknown
    """
    output = []
    delimiter = ','
    try:
      for i in seq:
        oid, value = i[0]
        if oid in OID_NAME:
          new_value = self._AttributeValueToString(value)
          output.append('%s=%s' % (OID_NAME[oid], new_value))
        else:
          raise CertificateParseError('Unknown OID %s' % str(oid))
    except (IndexError, ValueError, TypeError):
      raise CertificateParseError('Unknown DN sequence structure', seq)
    return delimiter.join(output)

  def _GetFieldsFromSequence(self, seq):
    """Get cert fields from a sequence.

    Args:
      seq: pyasn1.type.univ.Sequence
    Returns:
      dict {
          'serial_num': int,
          'issuer': unicode,
          'subject': unicode,
          'valid_notbefore': datetime.datetime,
          'valid_notafter': datetime.datetime,
          'fields_data': str, field data as ASN1 DER encoded,
          'sig_data': str, sig data as ASN1 DER encoded,
          'sig_algorithm': str, sig algorithm,
          'may_act_as_ca': bool or None if unknown,
          'key_usage': tuple, of items from X509V3_KEY_USAGE_BIT_FIELDS,
      }
    Raises:
      CertificateParseError: the certificate isn't constructed
        as expected way and cannot be parsed
      CertificateValueError: error in a value in the certificate
    """
    try:
      # Certificate Fields.  See RFC, section 4.1
      # must have at least as many fields as we are searching for.
      # length is likely 8.
      if len(seq) < 6:
        raise CertificateParseError('Too few certificate field sequences')

      # only support version 3 at this time because this code looks for
      # the x509v3 extensions in sequence 7.
      if seq[0] != X509_CERT_VERSION_3:
        raise CertificateParseError('X509 version %s not supported' % seq[0])

      # get serial number
      serial_num = int(seq[1])

      # get signature algorithm
      cert_sig_algorithm = self._GetSignatureAlgorithmFromSequence(seq[2])

      # get issuer
      cert_issuer = self._AssembleDNSequence(seq[3])

      # get validity time
      if (seq[4][0].isSameTypeWith(pyasn1.type.useful.UTCTime()) and
          seq[4][1].isSameTypeWith(pyasn1.type.useful.UTCTime())):
        (before_ts, after_ts) = seq[4]
        cert_valid_notbefore = self._CertTimestampToDatetime(before_ts)
        cert_valid_notafter = self._CertTimestampToDatetime(after_ts)
      else:
        raise CertificateParseError('Validity time structure')

      # get subject
      cert_subject = self._AssembleDNSequence(seq[5])

      # parse X509V3 extensions
      if len(seq) > 7:
        v3_output = self._GetV3ExtensionFieldsFromSequence(seq[7])
      else:
        v3_output = {}

      # produce binary version of the certificate fields
      # for later use when verifying CA signature
      fields_data = der_encoder.encode(seq)

      # put all values together
      output = {
          'serial_num': serial_num,
          'issuer': unicode(cert_issuer),
          'subject': unicode(cert_subject),
          'valid_notbefore': cert_valid_notbefore,
          'valid_notafter': cert_valid_notafter,
          'fields_data': fields_data,
          'sig_algorithm': cert_sig_algorithm,
      }
      # add the v3 extended output
      output.update(v3_output)

    except (IndexError, TypeError, AttributeError, ValueError), e:
      raise CertificateParseError(str(e))

    return output

  def _GetSignatureAlgorithmFromSequence(self, seq):
    """Get signature algorithm from a sequence.

    Args:
      seq: pyasn1.type.univ.Sequence
    Returns:
      dict {
          'sig_type': str OID value
      }
    Raises:
      CertificateParseError: the certificate isn't constructed
        as expected way and cannot be parsed
      CertificateValueError: error in a value in the certificate
    """
    try:
      # RFC 4.1.1.2
      if len(seq) != 2:
        raise CertificateParseError('Cannot parse signature algorithm')

      if seq[0] not in self.SIGNATURE_ALGORITHMS:
        raise CertificateValueError(
            'Unsupported signature algorithm %s' % str(seq[0]))

      output = {'sig_algorithm': seq[0]}
    except (IndexError, TypeError, AttributeError), e:
      raise CertificateParseError(str(e))

    return output

  def _GetSignatureFromSequence(self, seq):
    """Get signature from a sequence.

    Args:
      seq: pyasn1.type.univ.Sequence
    Returns:
      dict {
          'sig_data': str, signature data as ASN1 encoded
      }
    Raises:
      CertificateParseError: the certificate isn't constructed
        as expected way and cannot be parsed
    """
    try:
      if len(seq) >= 1024:
        total = 0
        # is it just a bit list?
        for b in seq:
          total |= seq[b]
        if total not in [0, 1]:
          raise CertificateParseError('Invalid signature format')
      else:
        raise CertificateParseError('Signature length must be >=1024')

      # the signature data
      sig_data = der_encoder.encode(seq)
      # skip header bytes, which may vary in size due to the way BER/DER
      # can encode one same thing in different ways.  use the original
      # bit length to guide us to the correct length instead of trying
      # to read the header.
      sig_data = sig_data[-1 * (len(seq)/8):]

      output = {'sig_data': sig_data}

    except (IndexError, TypeError, AttributeError), e:
      raise CertificateParseError(str(e))

    return output

  def _GetCertSequencesFromTopSequence(self, seq):
    """Get RFC 3280 cert sequences from top sequence.

    Args:
      seq: pyasn1.type.univ.Sequence
    Returns:
      dict combining all _Get* output
    Raises:
      CertificateParseError: the certificate isn't constructed
        as expected way and cannot be parsed
      CertificateValueError: error in a value in the certificate
    """
    # The structure below is defined in:
    # http://www.ietf.org/rfc/rfc3280.txt

    if type(seq) is not tuple or len(seq) < 1:
      raise CertificateParseError(
          'Top of certificate should consist of 1+ sequences')

    # the x509 cert starts out with one top level sequence.
    seq = seq[0]

    # the x509 cert should only have a few top-level sequences in it.
    # they are:
    #   Certificate Fields   [0]
    #   signatureAlgorithm   [1]
    #   signatureValue       [2]
    fields = self._GetFieldsFromSequence(seq[0])
    sigalg = self._GetSignatureAlgorithmFromSequence(seq[1])
    sig = self._GetSignatureFromSequence(seq[2])

    cert = {}
    cert.update(fields)
    cert.update(sigalg)
    cert.update(sig)
    return cert

  def _GetPublicKeyFromByteString(self, bytes_str):
    """Get the public key from a byte string.

    Args:
      bytes_str: str, byte string for entire certificate
    Returns:
      dictionary like = {
          'public_key': tlslite.utils.RSAKey.RSAKey object
      }
    """
    cert = tlslite_bridge.X509()
    cert.parseBinary(bytearray(bytes_str))
    return {
        'public_key': cert.publicKey,
    }

  def LoadFromByteString(self, bytes_str):
    """Load certificate contents from a byte string.

    Args:
      bytes_str: str, bytes
    """
    # break the client cert into pieces
    try:
      c = der_decoder.decode(bytes_str)
    except pyasn1.error.PyAsn1Error, e:
      raise CertificateASN1FormatError('DER decode: %s' % str(e))

    cert = {
        'entire_byte_string': bytes_str,
    }
    cert.update(self._GetCertSequencesFromTopSequence(c))
    cert.update(self._GetPublicKeyFromByteString(bytes_str))
    self.Reset()
    self._cert.update(cert)

  def CheckValidity(self, utcnow=None):
    """Check that the certificate is still valid, given its validity time.

    Args:
      utcnow: datetime, optional, time to consider "now", in UTC
    Raises:
      CertificateValueError: a time parameter is not valid
    """
    if utcnow is None:
      utcnow = datetime.datetime.utcnow()

    if utcnow > self._cert['valid_notafter']:
      raise CertificateValueError(
          'Certificate expired on %s' % self._cert['valid_notafter'])

    if utcnow < self._cert['valid_notbefore']:
      raise CertificateValueError(
          'Certificate not valid until %s' % self._cert['valid_notbefore'])

  def CheckIssuer(self, issuer=None):
    """Check that the certificate has a specific issuer.

    Args:
      issuer: str, optional, issuer that is required
    Raises:
      CertificateValueError: if issuer does not match
    """
    if issuer is None:
      issuer = self._required_issuer

    if issuer is None:
      return

    if self._cert['issuer'] is None or self._cert['issuer'] != issuer:
      raise CertificateValueError(
          'Issuer does not match required issuer: "%s" != required "%s"' % (
              self._cert['issuer'], issuer))

  def CheckAll(self):
    """Check all.

    Raises:
      CertificateValueError: if the certificate does not check
    """
    self.CheckValidity()
    self.CheckIssuer()

  def SetRequiredIssuer(self, issuer):
    """Set the required issuer.

    Args:
      issuer: str, like 'CN=foohost.foodomain.tld'
    """
    self._required_issuer = issuer

  def IsSignedBy(self, other_cert):
    """Check that this cert was signed by another cert.

    Args:
      other_cert: X509Certificate object for the other cert
    Returns:
      True if so
      False if not
    Raises:
      CertificateValueError: if the other cert is not a CA cert
    """
    if not other_cert.GetMayActAsCA():
      raise CertificateValueError('Other cert is not a CA cert')

    sig = tlslite_bridge.StrToArray(self.GetSignatureData())
    fields = tlslite_bridge.StrToArray(self.GetFieldsData())
    pk = other_cert.GetPublicKey()

    if self._cert['sig_algorithm'] == OID_SHA256_WITH_RSA_ENC:
      # tlslite doesn't support SHA256, so manually construct bytes to verify.
      fields_digest = hashlib.sha256(fields).digest()
      hash_bytes = tlslite_bridge.StrToArray(fields_digest)
      prefix_bytes = tlslite_bridge.StrToArray([
          48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32])
      return pk.verify(sig, prefix_bytes + hash_bytes)
    else:
      return pk.hashAndVerify(sig, fields)


def LoadPemGeneric(s, header, footer, skip_info=True):
  """Load a generic pem format string.

  Args:
    s: str, item in pem format
    header: str, header type to look for, e.g. "BEGIN CERTIFICATE"
    footer: str, footer type to look for, e.g. "END CERTIFICATE"
    skip_info: bool, default True, skip info lines like "Info...: .."
  Returns:
    list, lines of PEM format, including headers, no newlines.
  Raises:
    PEMFormatError: general format error.
    HeaderMissingPEMFormatError: header is missing.
    FooterMissingPEMFormatError: footer is missing.
  """
  lines = s.strip().split('\n')

  if len(lines) < 3:
    raise PEMFormatError('Certificate truncated/too few lines')

  begin = None
  end = None
  header = '-----%s-----' % header
  footer = '-----%s-----' % footer

  i = 0
  while i < len(lines):
    lines[i] = lines[i].strip()
    if lines[i] == header:
      begin = i
    elif begin is not None:
      if lines[i] == footer:
        end = i
      elif skip_info and lines[i].find(':') > -1:
        del lines[i]
    i += 1

  if begin is None:
    raise HeaderMissingPEMFormatError('PEM header is missing: %s' % header)

  if end is None:
    raise FooterMissingPEMFormatError('PEM footer is missing: %s' % footer)

  return lines[begin:end+1]


def LoadCertificateFromBase64(s):
  """Load a certificate from base64 format.

  Args:
    s: str, certificate in base64 format, no newlines, no non-b64 chars
  Returns:
    X509Certificate object
  Raises:
    PEMFormatError: When the base64 body cannot be decoded.
    CertificateError: From LoadFromByteString(), certificate specific error.
  """
  if not BASE64_RE.search(s):
    raise PEMFormatError('Not valid base64')

  try:
    d = base64.b64decode(s)
  except TypeError, e:
    raise PEMFormatError('base64 decode error: %s' % str(e))

  x = X509Certificate()
  x.LoadFromByteString(d)
  return x


def LoadCertificateFromPEM(s):
  """Load a certificate from PEM format.

  Args:
    s: str, certificate in PEM format, including newlines
  Returns:
    X509Certificate object
  Raises:
    PEMFormatError: general format error.
    HeaderMissingPEMFormatError: header is missing.
    FooterMissingPEMFormatError: footer is missing.
    CertificateError: error in the certificate itself (not the way it is
      armored into PEM).
  """
  lines = LoadPemGeneric(s, 'BEGIN CERTIFICATE', 'END CERTIFICATE')
  # LoadCertificateFromBase64 func does not expect to receive the headers.
  pem_cert = ''.join(lines[1:-1])
  return LoadCertificateFromBase64(pem_cert)


def LoadRSAPrivateKeyFromPEM(s):
  """Load a RSA Private key from PEM format.

  Args:
    s: str, key in PEM format, including newlines
  Returns:
    X509Certificate object
  Raises:
    PEMFormatError: general format error.
    HeaderMissingPEMFormatError: header is missing.
    FooterMissingPEMFormatError: footer is missing.
    RSAPrivateKeyPEMFormatError: the RSA priv key cannot be loaded.
  """
  lines = LoadPemGeneric(s, 'BEGIN RSA PRIVATE KEY', 'END RSA PRIVATE KEY')
  # tlslite expects to see the header too.
  pem_rsa_key = '\n'.join(lines)
  try:
    return tlslite_bridge.parsePEMKey(pem_rsa_key)
  except SyntaxError, e:
    raise RSAPrivateKeyPEMFormatError(str(e))
