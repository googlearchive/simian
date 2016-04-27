#!/usr/bin/env python
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
"""x509 module tests."""



import types
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from pyasn1.type import univ
from simian.auth import x509


class Error(Exception):
  """Base Error."""


class X509ModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testLoadPemGeneric(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END'

    input =  '\n\n\n-----BEGIN-----\nhello\n-----END-----\n\n\n'
    expected = [
        '-----BEGIN-----',
        'hello',
        '-----END-----',
    ]

    self.assertEqual(expected, x509.LoadPemGeneric(input, header, footer))

  def testLoadPemGenericWhenInfo(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END'

    input =  ('\n\n\n-----BEGIN-----\n'
              'Proc-Type: foo\nhello\n-----END-----\n\n\n')
    expected = [
        '-----BEGIN-----',
        'hello',
        '-----END-----',
    ]

    self.assertEqual(expected, x509.LoadPemGeneric(input, header, footer))


  def testLoadPemGenericWhenSpaces(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END'

    input =  '   \n\n\n-----BEGIN-----   \nhello   \n-----END-----  \n\n\n  '
    expected = [
        '-----BEGIN-----',
        'hello',
        '-----END-----',
    ]

    self.assertEqual(expected, x509.LoadPemGeneric(input, header, footer))

  def testLoadPemGenericWhenSpacesNoLastNewline(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END'

    input =  '   \n\n\n-----BEGIN-----   \nhello   \n-----END-----'
    expected = [
        '-----BEGIN-----',
        'hello',
        '-----END-----',
    ]

    self.assertEqual(expected, x509.LoadPemGeneric(input, header, footer))

  def testLoadPemGenericWhenMissingHeader(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN BLAH'
    footer = 'END BLAH'

    input =  '\n\n\n-----BEGIN-----\nhello\n-----END-----\n\n\n'

    self.assertRaises(
        x509.HeaderMissingPEMFormatError, x509.LoadPemGeneric,
        input, header, footer)

  def testLoadPemGenericWhenMissingFooter(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END BLAH'

    input =  '\n\n\n-----BEGIN-----\nhello\n-----END-----\n\n\n'

    self.assertRaises(
        x509.FooterMissingPEMFormatError, x509.LoadPemGeneric,
        input, header, footer)

  def testLoadPemGenericWhenTooFewLines(self):
    """Test LoadPemGeneric()."""
    header = 'BEGIN'
    footer = 'END BLAH'

    input =  '\n\n\n-----BEGIN-----\n\n\n\n'

    self.assertRaises(
        x509.PEMFormatError, x509.LoadPemGeneric, input, header, footer)

  def testLoadCertificateFromPEM(self):
    """Test LoadCertificateFromPEM()."""
    header = 'BEGIN CERTIFICATE'
    footer = 'END CERTIFICATE'

    pem_input = 'pem_input'
    pem_output = ['---header---', 'base64', '---footer---']

    self.mox.StubOutWithMock(x509, 'LoadPemGeneric')
    self.mox.StubOutWithMock(x509, 'LoadCertificateFromBase64')
    x509.LoadPemGeneric(pem_input, header, footer).AndReturn(pem_output)
    x509.LoadCertificateFromBase64('base64').AndReturn('ok')

    self.mox.ReplayAll()
    self.assertEqual(x509.LoadCertificateFromPEM(pem_input), 'ok')
    self.mox.VerifyAll()

  def testLoadRSAPrivateKeyFromPEM(self):
    """Test LoadRSAPrivateKeyFromPEM()."""
    header = 'BEGIN RSA PRIVATE KEY'
    footer = 'END RSA PRIVATE KEY'

    pem_input = 'pem_input'
    pem_output = ['---header---', 'base64', '---footer---']

    self.mox.StubOutWithMock(x509, 'LoadPemGeneric')
    self.mox.StubOutWithMock(
        x509.tlslite_bridge, 'parsePEMKey')
    x509.LoadPemGeneric(pem_input, header, footer).AndReturn(pem_output)
    x509.tlslite_bridge.parsePEMKey(
        '\n'.join(pem_output)).AndReturn('ok')

    self.mox.ReplayAll()
    self.assertEqual(x509.LoadRSAPrivateKeyFromPEM(pem_input), 'ok')
    self.mox.VerifyAll()

  def testLoadRSAPrivateKeyFromPEMWhenSyntaxError(self):
    """Test LoadRSAPrivateKeyFromPEM()."""
    header = 'BEGIN RSA PRIVATE KEY'
    footer = 'END RSA PRIVATE KEY'

    pem_input = 'pem_input'
    pem_output = ['---header---', 'base64', '---footer---']

    self.mox.StubOutWithMock(x509, 'LoadPemGeneric')
    self.mox.StubOutWithMock(
        x509.tlslite_bridge, 'parsePEMKey')
    x509.LoadPemGeneric(pem_input, header, footer).AndReturn(pem_output)
    x509.tlslite_bridge.parsePEMKey(
        '\n'.join(pem_output)).AndRaise(SyntaxError)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.RSAPrivateKeyPEMFormatError,
        x509.LoadRSAPrivateKeyFromPEM, pem_input)
    self.mox.VerifyAll()

  def testLoadCertificateFromBase64(self):
    """Test LoadCertificateFromBase64()."""
    self.mox.StubOutWithMock(x509.base64, 'b64decode')
    self.mox.StubOutWithMock(x509, 'BASE64_RE')

    x509.BASE64_RE.search('b64str').AndReturn(True)
    x509.base64.b64decode('b64str').AndReturn('binary')

    mock_x509 = self.mox.CreateMockAnything()
    self.stubs.Set(x509, 'X509Certificate', mock_x509)
    mock_x509().AndReturn(mock_x509)
    mock_x509.LoadFromByteString('binary').AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        mock_x509,
        x509.LoadCertificateFromBase64('b64str'))
    self.mox.VerifyAll()

  def testLoadCertificateFromBase64WhenBase64CharacterCheckFail(self):
    """Test LoadCertificateFromBase64()."""
    self.mox.StubOutWithMock(x509.base64, 'b64decode')
    self.mox.StubOutWithMock(x509, 'BASE64_RE')

    x509.BASE64_RE.search('b64str').AndReturn(None)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.PEMFormatError,
        x509.LoadCertificateFromBase64, 'b64str')
    self.mox.VerifyAll()

  def testLoadCertificateFromBase64WhenBase64DecodeFail(self):
    """Test LoadCertificateFromBase64()."""
    self.mox.StubOutWithMock(x509.base64, 'b64decode')
    self.mox.StubOutWithMock(x509, 'BASE64_RE')

    x509.BASE64_RE.search('b64str').AndReturn(True)
    x509.base64.b64decode('b64str').AndRaise(TypeError)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.PEMFormatError,
        x509.LoadCertificateFromBase64, 'b64str')
    self.mox.VerifyAll()


class BaseDataObjectTest(mox.MoxTestBase):
  """Test BaseDataObject class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.bdo = x509.BaseDataObject()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGetDataDict(self):
    """Test _GetDataDict()."""
    try:
      self.bdo._GetDataDict()
      self.fail('NotImplementedError not raised')
    except NotImplementedError:
      pass

  def testCreateGetMethod(self):
    """Test CreateGetMethod()."""

    mock_dataobj = self.mox.CreateMockAnything()
    mock_dataobj._GetDataDict().AndReturn({'foo': 123})

    def mock_setattr(cls, key, value):
      self.assertEquals(key, 'GetFoo')
      self.assertTrue(type(value) is types.FunctionType)
      self.assertEqual(123, value(mock_dataobj))

    self.mox.ReplayAll()
    x509.BaseDataObject.CreateGetMethod('Foo', 'foo', setattr_=mock_setattr)
    self.mox.VerifyAll()


class X509CertificateTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.x = x509.X509Certificate()
    self._cert_reset = {
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

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _CheckSaneCertFields(self, d):
    """Check that output dict keys are defined in _cert_reset.

    Args:
      d: dict, output from a _Get*FromSequence method
    """
    for k in d:
      self.assertTrue(k in self._cert_reset, 'Key %s is invalid in _cert' % k)

  def testInit(self):
    """Test __init__()."""
    self.mox.StubOutWithMock(x509.X509Certificate, 'Reset')
    x509.X509Certificate.Reset().AndReturn(None)
    self.mox.ReplayAll()
    unused = x509.X509Certificate()
    self.mox.VerifyAll()

  def testReset(self):
    """Test Reset()."""
    self.x.Reset()
    self.assertEqual(self.x._cert, self._cert_reset)

  def testCreateGetMethods(self):
    """Test the autogenerated methods from CreateGetMethod()."""
    names = [
      'Issuer',
      'Subject',
      'DatetimeNotValidBefore',
      'DatetimeNotValidAfter',
      'FieldsData',
      'SignatureData',
      'SignatureAlgorithm',
      'SerialNumber',
      'EntireCertData',
      'PublicKey',
      'MayActAsCA',
      'KeyUsage',
      'SubjectAltName',
    ]

    for name in names:
      self.assertTrue(
          hasattr(self.x, 'Get%s' % name), 'has method Get%s' % name)
      self.assertTrue(
          type(getattr(self.x, 'Get%s' % name)) is types.MethodType,
          'Get%s is a method' % name)

  def testGetDataDict(self):
    """Test _GetDataDict()."""
    self.assertEqual(self.x._cert, self.x._GetDataDict())

  def testCertTimestampToDatetime(self):
    """Test _CertTimestampToDatetime()."""
    self.mox.StubOutWithMock(x509.time, 'strptime')
    self.mox.StubOutWithMock(x509.datetime, 'datetime', True)

    time_ary = (1981, 1, 11, 0, 0, 0, 0, 'bla')

    x509.time.strptime('ts', self.x.TIMESTAMP_FMT).AndReturn(time_ary)
    x509.datetime.datetime(*time_ary[0:7]).AndReturn('datetime')

    self.mox.ReplayAll()
    self.assertEqual('datetime', self.x._CertTimestampToDatetime('ts'))
    self.mox.VerifyAll()

  def testStrToArray(self):
    """Test _StrToArray()."""
    self.mox.StubOutWithMock(x509.array, 'array', True)
    x509.array.array('B', 's').AndReturn('ary')
    self.mox.ReplayAll()
    self.assertEqual('ary', self.x._StrToArray('s'))
    self.mox.VerifyAll()

  def testCertTimestampToDatetimeWhenBadTimestamp(self):
    """Test _CertTimestampToDatetime()."""
    self.mox.StubOutWithMock(x509.time, 'strptime')

    x509.time.strptime('ts', self.x.TIMESTAMP_FMT).AndRaise(ValueError)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateValueError,
        self.x._CertTimestampToDatetime, 'ts')
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDKeyUsage(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_key_usage = univ.OctetString('\x03e_key_usage')
    d_key_usage = ((1, 0, 1),)

    x509.der_decoder.decode(e_key_usage).AndReturn(d_key_usage)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_KEY_USAGE, e_key_usage),
    )

    output = {
        'key_usage': (
            x509.X509V3_KEY_USAGE_BIT_FIELDS[0],
            x509.X509V3_KEY_USAGE_BIT_FIELDS[2],
            ),
    }

    self.mox.ReplayAll()
    self.assertEqual(
        output,
        self.x._GetV3ExtensionFieldsFromSequence(seq))
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDKeyUsageBadParse(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    e_key_usage = univ.OctetString('e_key_usage')
    d_key_usage = ((1, 0, 1),)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_KEY_USAGE, e_key_usage),
    )

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetV3ExtensionFieldsFromSequence,
        seq)
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDBasicConstraint(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_basic_const = univ.OctetString('e_basic_const')
    d_basic_const = ((True,), '')

    x509.der_decoder.decode(e_basic_const).AndReturn(d_basic_const)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_BASIC_CONSTRAINTS, e_basic_const),
    )

    output = {
        'may_act_as_ca': True,
    }

    self.mox.ReplayAll()
    self.assertEqual(
        output,
        self.x._GetV3ExtensionFieldsFromSequence(seq))
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDBasicConstraintForm2(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_basic_const = univ.OctetString('e_basic_const')
    d_basic_const = ((True,), '')

    x509.der_decoder.decode(e_basic_const).AndReturn(d_basic_const)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_BASIC_CONSTRAINTS, True, e_basic_const),
    )

    output = {
        'may_act_as_ca': True,
    }

    self.mox.ReplayAll()
    self.assertEqual(
        output,
        self.x._GetV3ExtensionFieldsFromSequence(seq))
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDBasicConstraintBadForm(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_basic_const = univ.OctetString('e_basic_const')
    d_basic_const = ((True,), '')

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_BASIC_CONSTRAINTS, True, e_basic_const, 'what', 'ugh'),
    )

    output = {
        'may_act_as_ca': True,
    }

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetV3ExtensionFieldsFromSequence,
        seq)
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDBasicConstraintPaths(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_basic_const = univ.OctetString('e_basic_const')
    d_basic_const = ((True,), ['unsupported path data'])

    x509.der_decoder.decode(e_basic_const).AndReturn(d_basic_const)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_BASIC_CONSTRAINTS, e_basic_const),
    )

    output = {
        'may_act_as_ca': True,
    }

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetV3ExtensionFieldsFromSequence,
        seq)
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDSubjectAltName(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    e_mspn = univ.OctetString('\x30mspn der encoded')
    d_mspn = (
        (x509.OID_MS_NT_PRINCIPAL_NAME, 'foo'),
    )

    x509.der_decoder.decode(e_mspn).AndReturn(d_mspn)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_SUBJECT_ALT_NAME, e_mspn),
    )

    output = {
        'subject_alt_name': 'X_MS_NT_Principal_Name=foo',
    }

    self.mox.ReplayAll()
    self.assertEqual(
        output,
        self.x._GetV3ExtensionFieldsFromSequence(seq))
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDSubjectAltNameBadForm(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    e_mspn = univ.OctetString('mspn der encoded wrong encapsulation')
    d_mspn = (
        (x509.OID_MS_NT_PRINCIPAL_NAME, 'foo'),
    )

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_SUBJECT_ALT_NAME, e_mspn),
    )

    output = {
        'subject_alt_name': 'X_MS_NT_Principal_Name=foo',
    }

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetV3ExtensionFieldsFromSequence,
        seq)
    self.mox.VerifyAll()

  def testGetV3ExtensionFieldsFromSequenceWhenOIDSubjectAltNameUnknownOID(self):
    """Test _GetV3ExtensionFieldsFromSequence()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    unknown_oid = (1, 2, 3)
    e_mspn = univ.OctetString('\x30mspn der encoded')
    d_mspn = (
        (unknown_oid, 'foo'),
    )

    x509.der_decoder.decode(e_mspn).AndReturn(d_mspn)

    seq = (
      ('junk', ('value', 'value')),
      (x509.OID_X509V3_SUBJECT_ALT_NAME, e_mspn),
    )

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetV3ExtensionFieldsFromSequence,
        seq)
    self.mox.VerifyAll()

  def testAttributeValueToString(self):
    """Test _AttributeValueToString()."""
    value = 'newyork'
    expected = 'newyork'
    self.assertEqual(value, expected)
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringWhenLeadingBadCharsSpace(self):
    """Test _AttributeValueToString()."""
    value = ' new york'
    expected = '\\ new york'
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringWhenLeadingBadCharsHash(self):
    """Test _AttributeValueToString()."""
    value = '#new york'
    expected = '\\#new york'
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringWhenTrailingBadCharsSpace(self):
    """Test _AttributeValueToString()."""
    value = 'new york '
    expected = 'new york\\ '
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringWhenContainsNull(self):
    """Test _AttributeValueToString()."""
    value = 'new%syork' % chr(00)
    expected = 'new\\00york'
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringPreventIndexRegression(self):
    """Test _AttributeValueToString()."""
    value = ',newyork'
    expected = '\\,newyork'
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAttributeValueToStringWhenCharsNeedingEscaping(self):
    """Test _AttributeValueToString()."""
    chars = ['"', '+', ',', ';', '<', '>', '\\']
    for c in chars:
      value = 'new%syork' % c
      expected = 'new\\%syork' % c
      result = self.x._AttributeValueToString(value)
      self.assertEqual(expected, result)

  def testAttributeValueToStringWhenMultipleAdjacentTransformsNeeded(self):
    """Test _AttributeValueToString()."""
    value = ' new,york;; '
    expected = '\\ new\\,york\\;\\;\\ '
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)
    value = '#new,york;\x00, '
    expected = '\\#new\\,york\\;\\00\\,\\ '
    result = self.x._AttributeValueToString(value)
    self.assertEqual(expected, result)

  def testAssembleDNSequence(self):
    """Test _AssembleDNSequence()."""
    value = (
      ((x509.OID_ID['CN'], 'foo'),),
      ((x509.OID_ID['OU'], 'bar'),),
    )
    self.mox.StubOutWithMock(self.x, '_AttributeValueToString')
    self.x._AttributeValueToString('foo').AndReturn('foo')
    self.x._AttributeValueToString('bar').AndReturn('bar')
    self.mox.ReplayAll()
    self.assertEqual(self.x._AssembleDNSequence(value), 'CN=foo,OU=bar')
    self.mox.VerifyAll()

  def testAssembleDNSequenceWhenUnknownOID(self):
    """Test _AssembleDNSequence()."""
    bad_oid = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    value = (
      ((bad_oid, 'foo'),),
      ((x509.OID_ID['OU'], 'bar'),),
    )
    self.assertRaises(
        x509.CertificateParseError,
        self.x._AssembleDNSequence,
        value)

  def testAssembleDNSequenceWhenBadStructure(self):
    """Test _AssembleDNSequence()."""
    value = (
      (x509.OID_ID['CN'], 'foo'),     # bad structure
      ((x509.OID_ID['OU'], 'bar'),),
    )
    self.assertRaises(
        x509.CertificateParseError,
        self.x._AssembleDNSequence,
        value)

  def testGetFieldsFromSequence(self):
    """Test _GetFieldsFromSequence()."""
    sig_alg_seq = ('a','b')
    sig_alg = 'sigalg'
    before_ts = self.mox.CreateMockAnything()
    after_ts = self.mox.CreateMockAnything()
    mock_utctime = self.mox.CreateMockAnything()
    self.stubs.Set(x509.pyasn1.type.useful, 'UTCTime', mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    before_ts.isSameTypeWith(mock_utctime).AndReturn(True)
    after_ts.isSameTypeWith(mock_utctime).AndReturn(True)
    serial_num = 12345
    v3ext = {
        'may_act_as_ca': 123,
        'key_usage': (1, 2, 3),
        'subject_alt_name': 'subj alt name',
    }

    seq = (
        x509.X509_CERT_VERSION_3,
        serial_num,
        sig_alg_seq,
        (((x509.OID_ID['CN'], 'issuer'),),),
        (before_ts, after_ts),
        (((x509.OID_ID['CN'], 'subject'),),),
        'public key',
        'x509v3 extensions',
    )
    seq_encoded = 'raw bytes'
    before_dt = 'before_dt'
    after_dt = 'after_dt'

    self.mox.StubOutWithMock(self.x, '_GetSignatureAlgorithmFromSequence')
    self.mox.StubOutWithMock(self.x, '_CertTimestampToDatetime')
    self.mox.StubOutWithMock(self.x, '_GetV3ExtensionFieldsFromSequence')
    self.mox.StubOutWithMock(self.x, '_AssembleDNSequence')
    self.mox.StubOutWithMock(x509.der_encoder, 'encode', True)
    self.x._GetSignatureAlgorithmFromSequence(
        sig_alg_seq).AndReturn(sig_alg)
    self.x._AssembleDNSequence(seq[3]).AndReturn('CN=issuer')
    self.x._CertTimestampToDatetime(before_ts).AndReturn(before_dt)
    self.x._CertTimestampToDatetime(after_ts).AndReturn(after_dt)
    self.x._AssembleDNSequence(seq[5]).AndReturn('CN=subject')
    self.x._GetV3ExtensionFieldsFromSequence(seq[7]).AndReturn(v3ext)
    x509.der_encoder.encode(seq).AndReturn(seq_encoded)

    self.mox.ReplayAll()
    output = self.x._GetFieldsFromSequence(seq)
    self._CheckSaneCertFields(output)
    self.assertEqual(
        output, {
            'serial_num': serial_num,
            'issuer': u'CN=issuer',
            'subject': u'CN=subject',
            'valid_notbefore': before_dt,
            'valid_notafter': after_dt,
            'fields_data': seq_encoded,
            'sig_algorithm': sig_alg,
            'may_act_as_ca': v3ext['may_act_as_ca'],
            'key_usage': v3ext['key_usage'],
            'subject_alt_name': v3ext['subject_alt_name'],
        })
    self.mox.VerifyAll()

  def testGetFieldsFromSequenceWhenSeqShort(self):
    """Test _GetFieldsFromSequence()."""
    serial_num = 12345

    seq = (
        x509.X509_CERT_VERSION_3,
        serial_num,
    )   # fails (length of entire sequence too short)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetFieldsFromSequence, seq)
    self.mox.VerifyAll()

  def testGetFieldsFromSequenceWhenWrongVersion(self):
    """Test _GetFieldsFromSequence()."""
    seq = (
        x509.X509_CERT_VERSION_3 * 2,  # fails
        1,
        2,
        3,
        4,
        5,
        6,
    )

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetFieldsFromSequence, seq)
    self.mox.VerifyAll()

  def testGetFieldsFromSequenceWhenValidityNotBeforeFail(self):
    """Test _GetFieldsFromSequence()."""
    sig_alg_seq = ('a','b')
    sig_alg = 'sigalg'
    before_ts = self.mox.CreateMockAnything()
    after_ts = self.mox.CreateMockAnything()
    mock_utctime = self.mox.CreateMockAnything()
    self.stubs.Set(x509.pyasn1.type.useful, 'UTCTime', mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    before_ts.isSameTypeWith(mock_utctime).AndReturn(False)  # fails
    serial_num = 12345
    bad_oid_cn = (9) * 10

    seq = (
        x509.X509_CERT_VERSION_3,
        serial_num,
        sig_alg_seq,
        (((x509.OID_ID['CN'], 'issuer'),),),
        (before_ts, after_ts),
        (((x509.OID_ID['CN'], 'subject'),),),
        'public key',
        'x509v3 extensions',
    )

    self.mox.StubOutWithMock(self.x, '_GetSignatureAlgorithmFromSequence')
    self.mox.StubOutWithMock(self.x, '_AssembleDNSequence')
    self.x._GetSignatureAlgorithmFromSequence(
        sig_alg_seq).AndReturn(sig_alg)
    self.x._AssembleDNSequence(seq[3]).AndReturn('CN=issuer')

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetFieldsFromSequence, seq)
    self.mox.VerifyAll()

  def testGetFieldsFromSequenceWhenValidityNotAfterFail(self):
    """Test _GetFieldsFromSequence()."""
    sig_alg_seq = ('a','b')
    sig_alg = 'sigalg'
    before_ts = self.mox.CreateMockAnything()
    after_ts = self.mox.CreateMockAnything()
    mock_utctime = self.mox.CreateMockAnything()
    self.stubs.Set(x509.pyasn1.type.useful, 'UTCTime', mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    before_ts.isSameTypeWith(mock_utctime).AndReturn(True)
    after_ts.isSameTypeWith(mock_utctime).AndReturn(False)  # fails
    serial_num = 12345
    bad_oid_cn = (9) * 10

    seq = (
        x509.X509_CERT_VERSION_3,
        serial_num,
        sig_alg_seq,
        (((x509.OID_ID['CN'], 'issuer'),),),
        (before_ts, after_ts),
        (((x509.OID_ID['CN'], 'subject'),),),
        'public key',
        'x509v3 extensions',
    )

    self.mox.StubOutWithMock(self.x, '_GetSignatureAlgorithmFromSequence')
    self.mox.StubOutWithMock(self.x, '_AssembleDNSequence')
    self.x._GetSignatureAlgorithmFromSequence(
        sig_alg_seq).AndReturn(sig_alg)
    self.x._AssembleDNSequence(seq[3]).AndReturn('CN=issuer')

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetFieldsFromSequence, seq)
    self.mox.VerifyAll()

  def testGetFieldsFromSequenceWhenX509V3Missing(self):
    """Test _GetFieldsFromSequence()."""
    sig_alg_seq = ('a','b')
    sig_alg = 'sigalg'
    before_ts = self.mox.CreateMockAnything()
    after_ts = self.mox.CreateMockAnything()
    mock_utctime = self.mox.CreateMockAnything()
    self.stubs.Set(x509.pyasn1.type.useful, 'UTCTime', mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    mock_utctime().AndReturn(mock_utctime)
    before_ts.isSameTypeWith(mock_utctime).AndReturn(True)
    after_ts.isSameTypeWith(mock_utctime).AndReturn(True)
    serial_num = 12345
    v3ext = { 'may_act_as_ca': 123, 'key_usage': (1, 2, 3) }

    seq = (
        x509.X509_CERT_VERSION_3,
        serial_num,
        sig_alg_seq,
        (((x509.OID_ID['CN'], 'issuer'),),),
        (before_ts, after_ts),
        (((x509.OID_ID['CN'], 'subject'),),),
        'public key',
    )
    seq_encoded = 'raw bytes'
    before_dt = 'before_dt'
    after_dt = 'after_dt'

    self.mox.StubOutWithMock(self.x, '_GetSignatureAlgorithmFromSequence')
    self.mox.StubOutWithMock(self.x, '_CertTimestampToDatetime')
    self.mox.StubOutWithMock(self.x, '_AssembleDNSequence')
    self.mox.StubOutWithMock(x509.der_encoder, 'encode', True)
    self.x._GetSignatureAlgorithmFromSequence(
        sig_alg_seq).AndReturn(sig_alg)
    self.x._AssembleDNSequence(seq[3]).AndReturn('CN=issuer')
    self.x._CertTimestampToDatetime(before_ts).AndReturn(before_dt)
    self.x._CertTimestampToDatetime(after_ts).AndReturn(after_dt)
    self.x._AssembleDNSequence(seq[5]).AndReturn('CN=subject')
    x509.der_encoder.encode(seq).AndReturn(seq_encoded)

    self.mox.ReplayAll()
    output = self.x._GetFieldsFromSequence(seq)
    self._CheckSaneCertFields(output)
    self.assertEqual(
        output, {
            'serial_num': serial_num,
            'issuer': 'CN=issuer',
            'subject': 'CN=subject',
            'valid_notbefore': before_dt,
            'valid_notafter': after_dt,
            'fields_data': seq_encoded,
            'sig_algorithm': sig_alg,
        })
    self.mox.VerifyAll()

  def testGetSignatureAlgorithmFromSequence(self):
    """Test _GetSignatureAlgorithmFromSequence()."""
    alg = self.x.SIGNATURE_ALGORITHMS[0]
    seq = (alg, '')
    output = self.x._GetSignatureAlgorithmFromSequence(seq)
    self._CheckSaneCertFields(output)
    self.assertEqual(output['sig_algorithm'], alg)

  def testGetSignatureAlgorithmFromSequenceWhenBadOID(self):
    """Test _GetSignatureAlgorithmFromSequence()."""
    alg = (5, 4, 3, 2, 1)  # fake OID
    self.assertFalse(alg in self.x.SIGNATURE_ALGORITHMS)
    seq = (alg, '')
    self.assertRaises(
        x509.CertificateValueError,
        self.x._GetSignatureAlgorithmFromSequence, seq)

  def testGetSignatureAlgorithmFromSequenceWhenJunkSeq(self):
    """Test _GetSignatureAlgorithmFromSequence()."""
    alg = self.x.SIGNATURE_ALGORITHMS[0]
    seq = (alg, '', '', '')
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetSignatureAlgorithmFromSequence, seq)

  def testGetSignatureAlgorithmFromSequenceWhenJunk(self):
    """Test _GetSignatureAlgorithmFromSequence()."""
    seq = True
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetSignatureAlgorithmFromSequence, seq)

  def testGetSignatureFromSequence(self):
    """Test _GetSignatureFromSequence()."""
    bits = 1024
    good_seq = [1] * bits
    good_sig = (bits/8) * 'x'

    self.mox.StubOutWithMock(x509.der_encoder, 'encode', True)
    x509.der_encoder.encode(good_seq).AndReturn('junkJunkJUNK%s' % good_sig)

    self.mox.ReplayAll()
    output = self.x._GetSignatureFromSequence(good_seq)
    self._CheckSaneCertFields(output)
    self.assertEqual(output['sig_data'], good_sig)
    self.mox.VerifyAll()

  def testGetSignatureFromSequenceWhenShortSeq(self):
    """Test _GetSignatureFromSequence()."""
    short_seq = [1] * 5

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetSignatureFromSequence, short_seq)
    self.mox.VerifyAll()

  def testGetSignatureFromSequenceWhenNonBinarySeq(self):
    """Test _GetSignatureFromSequence()."""
    non_binary_seq = [2] * 2048

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetSignatureFromSequence, non_binary_seq)
    self.mox.VerifyAll()

  def testGetSignatureFromSequenceWhenJunkInput(self):
    """Test _GetSignatureFromSequence()."""
    junk_seq = ['a'] * 1024

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetSignatureFromSequence, junk_seq)
    self.mox.VerifyAll()

  def testGetCertSequencesFromTopSequence(self):
    """Test GetCertSequencesFromTopSequence()."""
    seq = ((0, 1, 2),)

    self.mox.StubOutWithMock(self.x, '_GetFieldsFromSequence')
    self.mox.StubOutWithMock(self.x, '_GetSignatureAlgorithmFromSequence')
    self.mox.StubOutWithMock(self.x, '_GetSignatureFromSequence')

    self.x._GetFieldsFromSequence(seq[0][0]).AndReturn({'a':1})
    self.x._GetSignatureAlgorithmFromSequence(seq[0][1]).AndReturn({'b':1})
    self.x._GetSignatureFromSequence(seq[0][2]).AndReturn({'c':1})

    self.mox.ReplayAll()
    o = self.x._GetCertSequencesFromTopSequence(seq)
    self.assertEqual(o, {'a':1, 'b':1, 'c':1})
    self.mox.VerifyAll()

  def testGetCertSequencesFromTopSequenceWhenBadTuple(self):
    """Test _GetCertSequencesFromTopSequence()."""
    seq = ()
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetCertSequencesFromTopSequence,
        seq)

    seq = 'not a tuple'
    self.assertRaises(
        x509.CertificateParseError,
        self.x._GetCertSequencesFromTopSequence,
        seq)

  def testGetPublicKeyFromByteString(self):
    """Test _GetPublicKeyFromByteString()."""
    bytes = 'bytes'
    publickey = 'publickey'

    self.mox.StubOutClassWithMocks(x509.tlslite_bridge, 'X509')
    mock_tls509 = x509.tlslite_bridge.X509()
    mock_tls509.parseBinary(bytes).AndReturn(None)
    mock_tls509.publicKey = publickey

    self.mox.ReplayAll()
    self.assertEqual(
        {'public_key': publickey},
        self.x._GetPublicKeyFromByteString(bytes))
    self.mox.VerifyAll()

  def testLoadFromByteString(self):
    """Test LoadFromByteString()."""
    self.x.Reset()
    base_cert = self.x._cert

    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)
    self.mox.StubOutWithMock(self.x, '_GetCertSequencesFromTopSequence')
    self.mox.StubOutWithMock(self.x, '_GetPublicKeyFromByteString')
    self.mox.StubOutWithMock(self.x, 'Reset')

    bytes = 'bytes'
    seq = 'seq'
    certseq = {'certseq': 1}
    pubkey = {'pubkey': 1}
    cert = { 'entire_byte_string': bytes }
    cert.update(base_cert)
    cert.update(certseq)
    cert.update(pubkey)

    x509.der_decoder.decode(bytes).AndReturn(seq)
    self.x._GetCertSequencesFromTopSequence(seq).AndReturn(certseq)
    self.x._GetPublicKeyFromByteString(bytes).AndReturn(pubkey)
    self.x.Reset().AndReturn(None)

    self.mox.ReplayAll()
    self.x.LoadFromByteString(bytes)
    self.assertEqual(self.x._cert, cert)
    self.mox.VerifyAll()

  def testLoadFromByteStringWhenPyAsn1Error(self):
    """Test LoadFromByteString()."""
    self.mox.StubOutWithMock(x509.der_decoder, 'decode', True)

    bytes = 'bytes'

    x509.der_decoder.decode(bytes).AndRaise(x509.pyasn1.error.PyAsn1Error)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateASN1FormatError,
        self.x.LoadFromByteString, bytes)
    self.mox.VerifyAll()

  def testCheckValidityWhenObtainUtc(self):
    """Test CheckValidity()."""
    mock_datetime = self.mox.CreateMock(x509.datetime.datetime)
    self.stubs.Set(x509.datetime, 'datetime', mock_datetime)
    mock_datetime.utcnow().AndReturn(2)
    self.x._cert['valid_notafter'] = 5
    self.x._cert['valid_notbefore'] = 0
    self.mox.ReplayAll()
    self.x.CheckValidity()
    self.mox.VerifyAll()

  def testCheckValidityWhenTooNew(self):
    """Test CheckValidity()."""
    self.x._cert['valid_notafter'] = 1

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateError,
        self.x.CheckValidity,
        2)
    self.mox.VerifyAll()

  def testCheckValidityWhenTooOld(self):
    """Test CheckValidity()."""
    self.x._cert['valid_notafter'] = 10
    self.x._cert['valid_notbefore'] = 5

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateError,
        self.x.CheckValidity,
        2)
    self.mox.VerifyAll()

  def testCheckIssuerWhenNoIssuerSupplied(self):
    """Test CheckIssuer()."""
    self.x._required_issuer = 'required'
    self.x._cert['issuer'] = 'required'
    self.mox.ReplayAll()
    self.x.CheckIssuer()
    self.mox.VerifyAll()

  def testCheckIssuerWhenFailed(self):
    """Test CheckIssuer()."""
    self.x._required_issuer = None
    self.x._cert['issuer'] = 'required'
    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateValueError,
        self.x.CheckIssuer, 'some other issuer')
    self.mox.VerifyAll()

  def testCheckIssuerWhenNoRequirement(self):
    """Test CheckIssuer()."""
    self.x._required_issuer = None
    self.x._cert['issuer'] = 'no one cares'
    self.mox.ReplayAll()
    self.x.CheckIssuer()
    self.mox.VerifyAll()

  def testCheckAll(self):
    """Test CheckAll()."""
    self.mox.StubOutWithMock(self.x, 'CheckValidity')
    self.mox.StubOutWithMock(self.x, 'CheckIssuer')
    self.x.CheckValidity().AndReturn(None)
    self.x.CheckIssuer().AndReturn(None)
    self.mox.ReplayAll()
    self.x.CheckAll()
    self.mox.VerifyAll()

  def testSetRequiredIssuer(self):
    """Test SetRequiredIssuer()."""
    self.x.SetRequiredIssuer('required')
    self.assertEqual(self.x._required_issuer, 'required')

  def testIsSignedBy(self):
    """Test IsSignedBy()."""
    self.mox.StubOutWithMock(self.x, '_StrToArray')
    self.mox.StubOutWithMock(self.x, 'GetSignatureData')
    self.mox.StubOutWithMock(self.x, 'GetFieldsData')
    mock_othercert = self.mox.CreateMockAnything()

    mock_othercert.GetMayActAsCA().AndReturn(True)
    mock_othercert.GetPublicKey().AndReturn(mock_othercert)  # lazy re-use
    self.x.GetSignatureData().AndReturn('sigdata')
    self.x.GetFieldsData().AndReturn('fieldsdata')
    self.x._StrToArray('sigdata').AndReturn('arysigdata')
    self.x._StrToArray('fieldsdata').AndReturn('aryfieldsdata')
    mock_othercert.hashAndVerify('arysigdata', 'aryfieldsdata').AndReturn(True)

    self.mox.ReplayAll()
    self.assertTrue(self.x.IsSignedBy(mock_othercert))
    self.mox.VerifyAll()

  def testIsSignedByWhenOtherCertNotCA(self):
    """Test IsSignedBy()."""
    mock_othercert = self.mox.CreateMockAnything()
    mock_othercert.GetMayActAsCA().AndReturn(False)

    self.mox.ReplayAll()
    self.assertRaises(
        x509.CertificateValueError,
        self.x.IsSignedBy, mock_othercert)
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
