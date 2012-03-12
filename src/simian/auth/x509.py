#!/usr/bin/env python
# 
# Copyright 2010 Google Inc. All Rights Reserved.
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
# #

"""Module with code to handle X509 certificates.

Classes:

  X509Certificate: class to load, hold, interpet a X509Certificate

Functions:

  LoadCertificateFromBase64: load a certificate from base64 string
  LoadCertificateFromPEMFormat: load a certificate from PEM format (e.g.
    OpenSSL command line tools output)
"""





import array
import base64
import datetime
import time
import pyasn1
import pyasn1.error
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
import pyasn1.type.useful
import tlslite
import tlslite.X509
import tlslite.utils.keyfactory


# OIDs as a dict, for quick lookup of the OID
OID_NAME = {
    (2, 5, 4, 3): 'CN',
    (2, 5, 4, 6): 'C',
    (2, 5, 4, 7): 'L',
    (2, 5, 4, 8): 'S',
    (2, 5, 4, 10): 'O',
    (2, 5, 4, 11): 'OU',
    (1, 2, 840, 113549, 1, 9, 1): 'emailAddress',
}

# OIDs as a dict, for quick lookup of the string, e.g. 'CN'
OID_ID = {}
for k, v in OID_NAME.iteritems():
  OID_ID[v] = k

# OID SHA1 Hash with RSA Encryption
# http://www.alvestrand.no/objectid/1.2.840.11359.html
OID_SHA1_WITH_RSA_ENC = (1, 2, 840, 113549, 1, 1, 5)

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


class Error(Exception):
  """Base Error."""


class CertificateError(Error):
  """Certificate Error."""


class CertificateValueError(CertificateError):
  """Error in a certificate value."""


class CertificateFormatError(CertificateError):
  """Certificate Format Error."""


class CertificateASN1FormatError(CertificateFormatError):
  """Certificate ASN1 Format Error."""


class CertificatePEMFormatError(CertificateFormatError):
  """Certificate PEM Format Error."""


class CertificateParseError(CertificateError):
  """Certificate cannot be parsed, an error in its structure."""


class BaseDataObject(object):
  """Object which can auto-generate its own Get* methods."""

  def _GetDataDict(self):
    """Returns the dictionary which holds instance data."""
    raise NotImplementedError

  @classmethod
  def CreateGetMethod(cls, name, key, _setattr=None):
    """Create a get method for a key which returns its value.

    Args:
      name: str, name for the method, e.g. "Foo"
      key: str, key in dict to retrieve, e.g. "foo"
      setattr: function, optional, used to set attribute on class
    """
    if _setattr is None:
      _setattr = setattr
    _setattr(cls, 'Get%s' % name, lambda self: self._GetDataDict()[key])


class X509Certificate(BaseDataObject):
  """X509 Certificate class."""

  SIGNATURE_ALGORITHMS = [OID_SHA1_WITH_RSA_ENC]
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

  def _StrToArray(self, s):
    """Return an array of bytes for a string.

    Args:
      s: str
    Returns:
      array.array instance
    """
    return array.array('B', s)

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
    try:
      for i in seq:
        oid, value = i[0]

        if oid in OID_NAME:
          output.append('%s=%s' % (OID_NAME[oid], value))
        else:
          raise CertificateParseError('Unknown OID %s' % str(oid))
    except (IndexError, ValueError, TypeError):
      raise CertificateParseError('Unknown DN sequence structure', seq)
    return ','.join(output)

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

  def _GetPublicKeyFromByteString(self, bytes):
    """Get the public key from a byte string.

    Args:
      bytes: str, byte string for entire certificate
    Returns:
      dictionary like = {
          'public_key': tlslite.utils.RSAKey.RSAKey object
      }
    """
    cert = tlslite.X509.X509()
    cert.parseBinary(bytes)
    return {
        'public_key': cert.publicKey,
    }

  def LoadFromByteString(self, bytes):
    """Load certificate contents from a byte string.

    Args:
      bytes: str, bytes
    """
    # break the client cert into pieces
    try:
      c = der_decoder.decode(bytes)
    except pyasn1.error.PyAsn1Error, e:
      raise CertificateASN1FormatError('DER decode: %s' % str(e))

    cert = {
        'entire_byte_string': bytes,
    }
    cert.update(self._GetCertSequencesFromTopSequence(c))
    cert.update(self._GetPublicKeyFromByteString(bytes))
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
          'Signature issuer does not match required issuer: %s != %s' % (
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

    return other_cert.GetPublicKey().hashAndVerify(
        self._StrToArray(self.GetSignatureData()),
        self._StrToArray(self.GetFieldsData()))


def LoadCertificateFromBase64(s):
  """Load a certificate from base64 format.

  Args:
    s: str, certificate in base64 format, no newlines
  Returns:
    X509Certificate object
  """
  d = base64.b64decode(s)
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
    CertificatePEMFormatError: When the certificate cannot be loaded.
  """
  lines = s.strip().split('\n')

  if lines[0] != '-----BEGIN CERTIFICATE-----':
    raise CertificatePEMFormatError('Missing begin certificate header')

  if lines[-1] != '-----END CERTIFICATE-----':
    raise CertificatePEMFormatError('Missing end certificate header')

  if len(lines) < 3:
    raise CertificatePEMFormatError('Missing certificate body')

  return LoadCertificateFromBase64(''.join(lines[1:-1]))