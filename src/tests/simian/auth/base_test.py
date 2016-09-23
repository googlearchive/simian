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
#
#

"""base module tests."""




import datetime
import logging


import mox
import stubout

from google.apputils import app
from google.apputils import basetest

from simian.auth import base

logging.basicConfig(filename='/dev/null')


class BaseModuleTest(basetest.TestCase):
  """Test the 'base' module."""

  def testConstants(self):
    self.assertTrue(base.MSG_SEP == ' ')
    self.assertTrue(type(base.AGE_TOKEN_SECONDS) is int)
    self.assertTrue(type(base.AGE_CN_SECONDS) is int)
    # sanity check: x < 10 minutes
    self.assertTrue(base.AGE_CN_SECONDS < 10*60*60)
    self.assertTrue(type(base.AGE_DEFAULT_SECONDS) is int)
    self.assertEqual(base.LEVEL_BASE, 0)
    self.assertEqual(base.LEVEL_ADMIN, 5)


class AuthTestingBase(mox.MoxTestBase):
  """Base class for all Auth class *tests* in this module."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.ba = self.GetTestClass()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def GetTestClass(self):
    raise NotImplementedError

  def AssertState(self, state):
    self.assertEqual(
        self.ba.State(), state,
        'State is %s, expected %s' % (self.ba.State(), state))

  def AssertAuthState(self, auth):
    self.assertEqual(self.ba.AuthState(), auth)

  def AssertInputFail(self, data):
    self.assertRaises(ValueError, self.ba.Input, data)

  def _MakeMsg(self, *items):
    return base.MSG_SEP.join(map(str, items))


class AuthSessionBaseTest(mox.MoxTestBase):
  """Test AuthSessionBase class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.asb = base.AuthSessionBase()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _AssertNIE(self, method_name, *args, **kwargs):
    """Assert that NotImplementedError is raised from a method call."""
    method = getattr(self.asb, method_name)
    self.assertRaises(
        NotImplementedError,
        method,
        *args,
        **kwargs)

  def testCreate(self):
    """Test _Create()."""
    self._AssertNIE('_Create', 'sid')

  def test_Get(self):
    """Test _Get()."""
    self._AssertNIE('_Get', 'sid')

  def testPut(self):
    """Test _Put()."""
    self._AssertNIE('_Put', 'session')

  def testGet(self):
    """Test Get()."""

  def testSet(self):
    """Test Set()."""
    sid = '12345'
    data = 'foo'
    foo = 'bar'

    session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.asb, '_Create')
    self.mox.StubOutWithMock(self.asb, '_Put')

    self.asb._Create(sid).AndReturn(session)
    self.asb._Put(session).AndReturn(None)
    self.asb._Create(sid).AndReturn(session)
    self.asb._Put(session).AndReturn(None)

    session.data = 'x'
    session.sid = sid

    self.mox.ReplayAll()
    self.asb.Set(sid, data)
    self.assertEqual(session.sid, sid)
    self.assertEqual(session.data, data)
    session.data = 'x'
    self.asb.Set(sid, foo=foo)
    self.assertEqual(session.data, None)
    self.assertEqual(session.foo, foo)
    self.mox.VerifyAll()

  def testGetWhenNotExist(self):
    """Test Get()."""
    sid = '12345'

    session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.asb, '_Get')

    self.asb._Get(sid).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(self.asb.Get(sid), None)
    self.mox.VerifyAll()

  def testGetWhenExpire(self):
    """Test Get()."""
    sid = '12345'

    session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.asb, '_Get')
    self.mox.StubOutWithMock(self.asb, 'ExpireOne')

    self.asb._Get(sid).AndReturn(session)
    self.asb.ExpireOne(session).AndReturn(True)

    self.mox.ReplayAll()
    self.assertEqual(self.asb.Get(sid), None)
    self.mox.VerifyAll()

  def testGetWhenData(self):
    """Test Get()."""
    sid = '12345'

    session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.asb, '_Get')
    self.mox.StubOutWithMock(self.asb, 'ExpireOne')

    self.asb._Get(sid).AndReturn(session)
    self.asb.ExpireOne(session).AndReturn(False)
    session.data = 'foo'

    self.mox.ReplayAll()
    self.assertEqual(self.asb.Get(sid), 'foo')
    self.mox.VerifyAll()

  def testGetWhenMultiData(self):
    """Test Get()."""
    sid = '12345'

    session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.asb, '_Get')
    self.mox.StubOutWithMock(self.asb, 'ExpireOne')

    self.asb._Get(sid).AndReturn(session)
    self.asb.ExpireOne(session).AndReturn(False)
    session.data = None
    session.foo = 'bar'

    self.mox.ReplayAll()
    self.assertEqual(self.asb.Get(sid), session)
    self.mox.VerifyAll()

  def testDeleteById(self):
    """Test DeleteById()."""
    self._AssertNIE('DeleteById', 'sid')

  def testDelete(self):
    """Test Delete()."""
    self._AssertNIE('Delete', 'session')

  def testAll(self):
    """Test All()."""
    self._AssertNIE('All')

  def testMtime(self):
    """Test _Mtime()."""
    session = self.mox.CreateMockAnything()
    session.mtime = 'foo'
    self.assertEqual(self.asb._Mtime(session), 'foo')

  def testNow(self):
    """Test _Now()."""
    now = datetime.datetime(1980, 1, 1, 0, 0, 0)
    self.stubs.Set(
        base.datetime, 'datetime',
        self.mox.CreateMock(base.datetime.datetime))
    base.datetime.datetime.utcnow().AndReturn(now)

    self.mox.ReplayAll()
    self.assertEqual(now, self.asb._Now())
    self.mox.VerifyAll()

  def testExpireOneTrue(self):
    """Test ExpireOne() where session is old enough to expire."""
    now = datetime.datetime.utcnow()
    asb = base.AuthSessionBase()
    session = self.mox.CreateMockAnything()

    session.mtime = now - datetime.timedelta(
        seconds=base.AGE_DEFAULT_SECONDS*2)

    self.mox.StubOutWithMock(asb, '_Now')
    self.mox.StubOutWithMock(asb, '_Mtime')
    self.mox.StubOutWithMock(asb, 'Delete')

    asb._Now().AndReturn(now)
    asb._Mtime(session).AndReturn(session.mtime)
    asb.Delete(session).AndReturn(None)

    self.mox.ReplayAll()
    self.assertTrue(asb.ExpireOne(session))
    self.mox.VerifyAll()

  def testExpireOneMtimeUndef(self):
    """Test ExpireOne() where session mtime is undefined."""
    now = datetime.datetime.utcnow()
    asb = base.AuthSessionBase()
    session = self.mox.CreateMockAnything()
    session.mtime = None

    self.mox.StubOutWithMock(asb, '_Now')
    self.mox.StubOutWithMock(asb, '_Mtime')
    self.mox.StubOutWithMock(asb, 'Delete')

    asb._Now().AndReturn(now)
    asb._Mtime(session).AndReturn(session.mtime)
    asb.Delete(session).AndReturn(None)

    self.mox.ReplayAll()
    self.assertTrue(asb.ExpireOne(session))
    self.mox.VerifyAll()

  def testExpireOneFalse(self):
    """Test ExpireOne() where session is not old enough to expire."""
    now = datetime.datetime.utcnow()
    asb = base.AuthSessionBase()
    session = self.mox.CreateMockAnything()

    session.mtime = now - datetime.timedelta(seconds=1)

    self.mox.StubOutWithMock(asb, '_Now')
    self.mox.StubOutWithMock(asb, '_Mtime')

    asb._Now().AndReturn(now)
    asb._Mtime(session).AndReturn(session.mtime)

    self.mox.ReplayAll()
    self.assertFalse(asb.ExpireOne(session))
    self.mox.VerifyAll()


class AuthSessionDataTest(mox.MoxTestBase):
  """Test AuthSessionData class."""

  def setUp(self):
    self.asd = base.AuthSessionData(foo='1')

  def testInit(self):
    """Test __init__()."""
    self.assertEqual(self.asd.foo, '1')

  def testContains(self):
    """Test __contains__()."""
    self.assertTrue('foo' in self.asd)
    self.assertFalse('bar' in self.asd)

  def testEq(self):
    """Test __eq__()."""
    self.assertEqual(self.asd, {'foo': '1'})
    self.assertNotEqual(self.asd, {'foo': 9})
    self.assertNotEqual(self.asd, {'other': 9})
    asd2 = base.AuthSessionData(foo='1')
    self.assertEqual(self.asd, asd2)
    asd2 = base.AuthSessionData(foo='2')
    self.assertNotEqual(self.asd, asd2)
    asd2 = base.AuthSessionData(other='2')
    self.assertNotEqual(self.asd, asd2)

  def testNotEq(self):
    other = base.AuthSessionData(foo='1')
    self.assertFalse(self.asd != other)


class AuthSessionDictTest(mox.MoxTestBase):
  """Test AuthSessionDict class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.asd = base.AuthSessionDict()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testCreate(self):
    """Test _Create()."""
    sid = '12345'
    now = 'now'

    self.mox.StubOutWithMock(self.asd, '_Now')
    self.asd._Now().AndReturn(now)

    mock_asdata = self.mox.CreateMockAnything()
    self.stubs.Set(base, 'AuthSessionData', mock_asdata)
    mock_asdata(sid=sid, mtime=now, data=None).AndReturn(-2)

    self.mox.ReplayAll()
    self.assertEqual(self.asd._Create(sid), -2)
    self.mox.VerifyAll()

  def testGet(self):
    """Test _Get()."""
    sid = '12345'
    self.asd._sessions = self.mox.CreateMockAnything()
    self.asd._sessions.get(sid, None).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(self.asd._Get(sid), None)
    self.mox.VerifyAll()

  def testPut(self):
    """Test _Put()."""
    self.asd._sessions = {}
    session = self.mox.CreateMockAnything()
    session.sid = '12345'
    self.mox.ReplayAll()
    self.asd._Put(session)
    self.assertEqual(self.asd._sessions['12345'], session)
    self.mox.VerifyAll()

  def testDeleteById(self):
    """Test DeleteById()."""
    self.asd._sessions = {'hi': 1, 'there': 2}
    self.asd.DeleteById('hi')
    self.assertEqual(['there'], self.asd._sessions.keys())
    self.asd.DeleteById('non-existent')
    self.assertEqual(['there'], self.asd._sessions.keys())

  def testDelete(self):
    """Test Delete()."""
    session = base.AuthSessionData(sid='a', other='other')

    self.mox.StubOutWithMock(self.asd, 'DeleteById')
    self.asd.DeleteById(session.sid).AndReturn(True)

    self.mox.ReplayAll()
    self.asd.Delete(session)
    self.mox.VerifyAll()

  def testAll(self):
    """Test All()."""

    sessions = {
        'a': base.AuthSessionData(sid='a', other='other'),
        'b': base.AuthSessionData(sid='b', other='whatever'),
    }

    self.asd._sessions = sessions
    found = []

    self.mox.ReplayAll()
    for session in self.asd.All():
      self.assertTrue(session.sid in sessions.keys())
      self.assertTrue(sessions[session.sid] is session)
      if session.sid not in found:
        found.append(session.sid)
    found.sort()
    self.assertEqual(found, ['a','b'])
    self.mox.VerifyAll()


class Auth1ServerSessionTest(mox.MoxTestBase):
  """Test Auth1ServerSession class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.a1ss = base.Auth1ServerSession()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testBasic(self):
    self.assertTrue(issubclass(self.a1ss.__class__, base.AuthSessionDict))
    self.assertTrue(hasattr(self.a1ss, 'SetCn'))
    self.assertTrue(hasattr(self.a1ss, 'GetToken'))


class Auth1ClientSessionTest(mox.MoxTestBase):
  """Test Auth1ClientSession class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.a1cs = base.Auth1ClientSession()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testBasic(self):
    self.assertTrue(issubclass(self.a1cs.__class__, base.AuthSessionDict))


class AuthBaseTest(AuthTestingBase):
  """Test for base.AuthBase class."""

  def GetTestClass(self):
    return base.AuthBase()

  def testResetState(self):
    """Test ResetState()."""
    self.ba._state = 'asdf'
    self.ba._auth_state = 'asdf'
    self.ba.ResetState()
    self.assertEqual(self.ba._state, self.ba._default_state)
    self.assertEqual(self.ba._auth_state, base.AuthState.UNKNOWN)

  def testAuthState(self):
    """Test AuthState()."""
    self.ba._auth_state = base.AuthState.UNKNOWN
    self.assertEqual(self.ba.AuthState(), base.AuthState.UNKNOWN)
    self.ba._auth_state = base.AuthState.OK
    self.assertEqual(self.ba.AuthState(), base.AuthState.OK)
    self.assertEqual(self.ba.AuthState(), base.AuthState.UNKNOWN)

  def testAuthStateOK(self):
    """Test AuthStateOK()."""
    self.mox.StubOutWithMock(self.ba, 'AuthState')
    self.ba.AuthState().AndReturn(base.AuthState.OK)
    self.ba.AuthState().AndReturn(base.AuthState.UNKNOWN)
    self.mox.ReplayAll()
    self.assertTrue(self.ba.AuthStateOK())
    self.assertFalse(self.ba.AuthStateOK())
    self.mox.VerifyAll()

  def testAddOutput(self):
    """Test _AddOutput()."""
    self.mox.ReplayAll()
    self.output = None
    self.assertEqual(self.ba._state, base.State.NONE)
    self.ba._AddOutput('out')
    self.assertEqual(self.ba._output, 'out')
    self.assertEqual(self.ba._state, base.State.OUTPUT)
    self.ba._AddOutput('more')
    self.assertEqual(self.ba._output, 'outmore')
    self.assertEqual(self.ba._state, base.State.OUTPUT)

    self.ba._output = None
    self.ba._AddOutput({'foo': 'bar'})
    self.assertEqual(self.ba._output, {'foo': 'bar'})
    self.assertEqual(self.ba._state, base.State.OUTPUT)
    self.ba._AddOutput({'more': 'ok'})
    self.assertEqual(self.ba._output, {'foo': 'bar', 'more': 'ok'})
    self.assertEqual(self.ba._state, base.State.OUTPUT)
    self.mox.VerifyAll()

  def testOutput(self):
    """Test Output()."""
    output = 'hello'
    self.ba._state = base.State.OUTPUT
    self.ba._output = output
    self.mox.ReplayAll()
    self.assertEqual(self.ba._state, base.State.OUTPUT)
    self.assertEqual(self.ba.Output(), output)
    self.assertEqual(self.ba._state, self.ba._default_state)
    self.mox.VerifyAll()

  def testOutputWhenNoOutput(self):
    """Test Output()."""
    self.mox.ReplayAll()
    self.ba._state = base.State.NONE
    self.assertEqual(self.ba.Output(), None)
    self.mox.VerifyAll()

  def testAddError(self):
    """Test _AddError()."""
    self.ba._error_output = None
    self.ba._AddError('1')
    self.assertEqual(self.ba._error_output, ['1'])
    self.ba._AddError('2')
    self.assertEqual(self.ba._error_output, ['1', '2'])

  def testErrorOutput(self):
    """Test ErrorOutput()."""
    self.ba._error_output = ['1', '2']
    self.assertEqual(self.ba.ErrorOutput(), ['1', '2'])

  def testAll(self):
    self.mox.ReplayAll()
    self.AssertState(base.State.NONE)
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.AssertInputFail('hello')
    self.AssertState(base.State.NONE)
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.assertEqual(self.ba.Output(), None)
    self.AssertState(base.State.NONE)
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.mox.VerifyAll()

  def testAuthFail(self):
    """Test AuthFail()."""
    self.ba.AuthFail()
    self.AssertState(self.ba.DefaultState())
    self.AssertAuthState(base.AuthState.FAIL)

  def testSplitMessage(self):
    """Test _SplitMessage()."""
    msg ='HELLO%sMSG' % base.MSG_SEP

    self.mox.ReplayAll()
    self.assertEqual(
        ['HELLO', 'MSG'],
        self.ba._SplitMessage('HELLO%sMSG' % base.MSG_SEP, 2))
    self.assertRaises(
        base.MessageError,
        self.ba._SplitMessage,
        'HELLO%sMSG' % base.MSG_SEP, 3)
    self.assertRaises(
        base.MessageError,
        self.ba._SplitMessage,
        'HELLO%sMSG%sHELLO' % (base.MSG_SEP, base.MSG_SEP), 2)
    self.mox.VerifyAll()

  def testAssembleMessage(self):
    """Test _AssembleMessage()."""
    inp = ['hi', 'there']
    outp = base.MSG_SEP.join(inp)
    self.assertEqual(outp, self.ba._AssembleMessage(*inp))


class Auth1Test(AuthTestingBase):
  """Test for base.Auth1 class."""

  def GetTestClass(self):
    return base.Auth1()

  def testNonce(self):
    """Test Nonce()."""
    random_bytes = 'a' * 16
    n = 129440743495415807670381713415221633377
    self.stubs.Set(base.os, 'urandom', self.mox.CreateMockAnything())
    base.os.urandom(16).AndReturn(random_bytes)
    self.mox.ReplayAll()
    self.assertEqual(self.ba.Nonce(), n)
    self.mox.VerifyAll()

  def testNonceBase64(self):
    """Test NonceBase64()."""
    self.mox.StubOutWithMock(self.ba, 'Nonce')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64encode')
    self.ba.Nonce().AndReturn(1)
    base.base64.urlsafe_b64encode('1').AndReturn('FakeB64')
    self.mox.ReplayAll()
    self.assertEqual(self.ba.NonceBase64(), 'FakeB64')
    self.mox.VerifyAll()

  def testGetCurrentEpochTimeUTC(self):
    """Test GetCurrentEpochTimeUTC()."""
    self.stubs.Set(
        base.datetime, 'datetime',
        self.mox.CreateMock(base.datetime.datetime))
    mock_datetime = self.mox.CreateMockAnything()
    base.datetime.datetime.utcnow().AndReturn(mock_datetime)
    mock_datetime.strftime('%s').AndReturn('123')
    self.mox.ReplayAll()
    self.assertEqual(123, self.ba.GetCurrentEpochTimeUTC())
    self.mox.VerifyAll()

  def testAuthToken(self):
    """Test _AuthToken()."""
    auth_token = 'foo'
    self.mox.StubOutWithMock(self.ba, 'NonceBase64')
    self.ba.NonceBase64().AndReturn(auth_token)
    self.mox.ReplayAll()
    self.ba._auth_state = base.AuthState.UNKNOWN
    self.assertEqual(None, self.ba._AuthToken())
    self.ba._auth_state = base.AuthState.OK
    self.assertEqual(auth_token, self.ba._AuthToken())
    self.mox.VerifyAll()

  def testLoadCert(self):
    """Test _LoadCert()."""
    certstr='pemcert'
    mock_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(base.x509, 'LoadCertificateFromPEM')
    base.x509.LoadCertificateFromPEM(certstr).AndReturn(mock_cert)
    base.x509.LoadCertificateFromPEM(certstr).AndRaise(base.x509.Error)

    self.mox.ReplayAll()
    self.assertEqual(mock_cert, self.ba._LoadCert(certstr))
    self.assertRaises(ValueError, self.ba._LoadCert, certstr)
    self.mox.VerifyAll()

  def testLoadKey(self):
    """Test _LoadKey()."""
    keystr='pemkey'
    self.stubs.Set(
        base.tlslite_bridge,
        'parsePEMKey',
        self.mox.CreateMockAnything())

    mock_key = self.mox.CreateMockAnything()

    base.tlslite_bridge.parsePEMKey(keystr).AndRaise(
        SyntaxError)

    base.tlslite_bridge.parsePEMKey(keystr).AndReturn(
        mock_key)

    self.mox.ReplayAll()
    self.assertRaises(ValueError, self.ba._LoadKey, keystr)
    self.assertEqual(self.ba._LoadKey(keystr), mock_key)
    self.mox.VerifyAll()

  def testSign(self):
    """Test Sign()."""
    data = 'hello'
    sig_bytes = base.array.array('B', 'signed')
    self.ba._key = self.mox.CreateMockAnything()
    self.ba._key.hashAndSign(base.array.array('B', data)).AndReturn(sig_bytes)
    self.mox.ReplayAll()
    self.assertEqual(self.ba.Sign(data), 'signed')
    self.mox.VerifyAll()

  def testSignWhenKeyNotLoaded(self):
    """Test Sign()."""
    data = 'hello'
    self.ba._key = None
    self.mox.ReplayAll()
    self.assertRaises(
        base.KeyNotLoaded,
        self.ba.Sign,
        data)
    self.mox.VerifyAll()

  def testLoadSelfKey(self):
    """Test LoadSelfKey()."""
    keystr = 'keystr'
    key = 'key'
    self.mox.StubOutWithMock(self.ba, '_LoadKey')
    self.ba._LoadKey(keystr).AndReturn(key)
    self.mox.ReplayAll()
    self.ba.LoadSelfKey(keystr)
    self.assertEqual(self.ba._key, key)
    self.mox.VerifyAll()

  def testLoadOtherCert(self):
    """Test LoadOtherCert()."""
    certstr = 'certstr'
    cert = 'cert'
    self.mox.StubOutWithMock(self.ba, '_LoadCert')
    self.ba._LoadCert(certstr).AndReturn(cert)
    self.mox.ReplayAll()
    self.assertEqual(self.ba.LoadOtherCert(certstr), cert)
    self.mox.VerifyAll()

  def testLoadSelfCert(self):
    """Test LoadSelfCert()."""
    certstr = 'certstr'
    cert = 'cert'
    self.mox.StubOutWithMock(self.ba, '_LoadCert')
    self.ba._LoadCert(certstr).AndReturn(cert)
    self.mox.ReplayAll()
    self.ba.LoadSelfCert(certstr)
    self.assertEqual(self.ba._cert, cert)
    self.mox.VerifyAll()

  def testVerifyCertSignedByCA(self):
    """Test VerifyCertSignedByCA()."""
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.ba._ca_pem = 'ca pem'
    mock_ca_cert = self.mox.CreateMockAnything()
    mock_cert = self.mox.CreateMockAnything()
    self.ba.LoadOtherCert(self.ba._ca_pem).AndReturn(mock_ca_cert)
    mock_cert.IsSignedBy(mock_ca_cert).AndReturn(True)
    self.mox.ReplayAll()
    self.assertTrue(self.ba.VerifyCertSignedByCA(mock_cert))
    self.mox.VerifyAll()

  def testVerifyDataSignedWithCert(self):
    """Test VerifyDataSignedWithCert()."""
    data = 'data'
    signature = 's' * 128

    mock_cert = self.mox.CreateMockAnything()
    mock_publickey = self.mox.CreateMockAnything()
    mock_publickey.n = 'modulus'

    mock_cert.GetPublicKey().AndReturn(mock_publickey)
    mock_publickey.hashAndVerify(
        base.array.array('B', signature),
        base.array.array('B', data)).AndReturn(-1)

    mock_cert.GetPublicKey().AndReturn(mock_publickey)

    mock_publickey.hashAndVerify(
        base.array.array('B', signature),
        base.array.array('B', data)).AndReturn(-1)

    self.mox.ReplayAll()
    self.ba._cert = None
    self.assertEqual(self.ba.VerifyDataSignedWithCert(
        data, signature, mock_cert), -1)
    self.ba._cert = mock_cert
    self.assertEqual(self.ba.VerifyDataSignedWithCert(
        data, signature), -1)
    self.mox.VerifyAll()

  def testVerifyDataSignedWithCertWhenShortSignature(self):
    """Test VerifyDataSignedWithCert()."""
    data = 'data'
    modulus_len = 128
    signature = 's' * (modulus_len - 2)   # short signature

    mock_cert = self.mox.CreateMockAnything()
    mock_publickey = self.mox.CreateMockAnything()
    mock_publickey.n = 'modulus'

    mock_cert.GetPublicKey().AndReturn(mock_publickey)
    mock_publickey.hashAndVerify(
        base.array.array('B', signature),
        base.array.array('B', data)).AndReturn(-1)

    mock_cert.GetPublicKey().AndReturn(mock_publickey)
    mock_publickey.hashAndVerify(
        base.array.array('B', signature),
        base.array.array('B', data)).AndReturn(-1)

    self.mox.ReplayAll()
    self.ba._cert = None
    self.assertEqual(self.ba.VerifyDataSignedWithCert(
        data, signature, mock_cert), -1)
    self.ba._cert = mock_cert
    self.assertEqual(self.ba.VerifyDataSignedWithCert(
        data, signature), -1)
    self.mox.VerifyAll()

  def testVerifyDataSignedWithCertWhenAssertionError(self):
    """Test VerifyDataSignedWithCert()."""
    data = 'data'
    signature = 'signature'

    mock_cert = self.mox.CreateMockAnything()
    mock_publickey = self.mox.CreateMockAnything()
    mock_cert.GetPublicKey().AndReturn(mock_publickey)

    mock_publickey.hashAndVerify(
        base.array.array('B', signature),
        base.array.array('B', data)).AndRaise(AssertionError)
    mock_publickey.n = 1000

    self.mox.ReplayAll()
    self.ba._cert = mock_cert
    self.assertRaises(
        base.CryptoError,
        self.ba.VerifyDataSignedWithCert,
        data, signature)
    self.mox.VerifyAll()

  def testSessionSetCnSn(self):
    """Test SessionSetCnSn()."""
    cn = '12345'
    sn = '54321'
    self.mox.StubOutWithMock(self.ba._session, 'SetCn')
    self.ba._session.SetCn(str(cn), str(sn)).AndReturn(None)
    self.mox.ReplayAll()
    self.ba.SessionSetCnSn(cn, sn)
    self.mox.VerifyAll()

  def testSessionVerifyKnownCnSn(self):
    """Test SessionVerifyKnownCnSn()."""
    cn = '12345'
    sn = '55555'
    self.mox.StubOutWithMock(self.ba._session, 'GetCn')
    self.ba._session.GetCn(str(cn)).AndReturn(None)
    self.ba._session.GetCn(str(cn)).AndReturn(sn * 2)
    self.ba._session.GetCn(str(cn)).AndReturn(sn)
    self.mox.ReplayAll()
    self.assertFalse(self.ba.SessionVerifyKnownCnSn(cn, sn))
    self.assertFalse(self.ba.SessionVerifyKnownCnSn(cn, sn))
    self.assertTrue(self.ba.SessionVerifyKnownCnSn(cn, sn))
    self.mox.VerifyAll()

  def testGetSessionIfAuthOK(self):
    """Test GetSessionIfAuthOK()."""
    token = 't12345'
    uuid = 'uuid'
    session = base.AuthSessionData(state=base.AuthState.OK, uuid=uuid)
    session_not_ok = base.AuthSessionData(state=base.AuthState.FAIL, uuid=uuid)
    self.mox.StubOutWithMock(self.ba._session, 'GetToken')

    self.ba._session.GetToken(token).AndReturn(None)
    self.ba._session.GetToken(token).AndReturn(session_not_ok)
    self.ba._session.GetToken(token).AndReturn(session)

    self.mox.ReplayAll()
    self.assertRaises(base.AuthSessionError, self.ba.GetSessionIfAuthOK, token)
    self.assertRaises(base.AuthSessionError, self.ba.GetSessionIfAuthOK, token)
    self.assertEqual(session, self.ba.GetSessionIfAuthOK(token))
    self.mox.VerifyAll()

  def testGetSessionIfAuthOKWhenRequiredLevel(self):
    """Test GetSessionIfAuthOK()."""
    token = 't12345'
    uuid = 'uuid'
    required_level = 2
    session_bad = base.AuthSessionData(
        state=base.AuthState.OK, uuid=uuid, level=required_level - 1)
    session_good = base.AuthSessionData(
        state=base.AuthState.OK, uuid=uuid, level=required_level + 1)

    self.mox.StubOutWithMock(self.ba._session, 'GetToken')

    self.ba._session.GetToken(token).AndReturn(session_bad)
    self.ba._session.GetToken(token).AndReturn(session_good)

    self.mox.ReplayAll()
    self.assertRaises(
        base.AuthSessionError,
        self.ba.GetSessionIfAuthOK, token, required_level)
    self.assertEqual(
        session_good, self.ba.GetSessionIfAuthOK(token, required_level))
    self.mox.VerifyAll()

  def testSessionGetUuid(self):
    """Test SessionGetUuid()."""
    token = 'abc'
    uuid = 'uuid'
    self.mox.StubOutWithMock(self.ba._session, 'GetToken')
    self.ba._session.GetToken(token).AndReturn(None)
    self.ba._session.GetToken(token).AndReturn(
        base.AuthSessionData(
            state=base.AuthState.OK, uuid=uuid))

    self.mox.ReplayAll()
    self.assertEqual(None, self.ba.SessionGetUuid(token))
    self.assertEqual(uuid, self.ba.SessionGetUuid(token))
    self.mox.VerifyAll()

  def testSessionCreateAuthToken(self):
    """Test SessionCreateAuthToken()."""
    token = 'abc'
    uuid = 'uuid'
    level = 123
    self.mox.StubOutWithMock(self.ba, '_AuthToken')
    self.mox.StubOutWithMock(self.ba._session, 'SetToken')
    self.ba._AuthToken().AndReturn(token)
    self.ba._session.SetToken(
        token, state=base.AuthState.OK, uuid=uuid, level=level).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(token, self.ba.SessionCreateAuthToken(uuid, level))
    self.mox.VerifyAll()

  def testSessionCreateUserAuthToken(self):
    """Test SessionCreateUserAuthToken()."""
    user = 'user'
    _level = 1
    token = 'token'

    def mock_cat(uuid, level):
      self.assertEqual(self.ba._auth_state, base.AuthState.OK)
      self.assertEqual(uuid, user)
      self.assertEqual(level, _level)
      return token

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    # stub this, not mock it, so that we can verify the _auth_state
    # at the moment of being called.
    self.stubs.Set(self.ba, 'SessionCreateAuthToken', mock_cat)
    self.ba.ResetState().AndReturn(None)
    self.ba.ResetState().AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(token, self.ba.SessionCreateUserAuthToken(user, _level))
    self.mox.VerifyAll()

  def testSessionDelCn(self):
    """Test SessionDelCn()."""
    cn = 'x'
    self.mox.StubOutWithMock(self.ba._session, 'DelCn')
    self.ba._session.DelCn(cn).AndReturn(None)
    self.mox.ReplayAll()
    self.ba.SessionDelCn(cn)
    self.mox.VerifyAll()

  def testSessionDelToken(self):
    """Test SessionDelToken()."""
    token = 'x'
    self.mox.StubOutWithMock(self.ba._session, 'DelToken')
    self.ba._session.DelToken(token).AndReturn(None)
    self.mox.ReplayAll()
    self.ba.SessionDelToken(token)
    self.mox.VerifyAll()

  def testInputWhenStep1BadCn(self):
    """Test Input()."""
    n = 'a'
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.ba.AuthFail().AndReturn(None)
    self.mox.ReplayAll()
    self.ba.Input(n=n)
    self.mox.VerifyAll()

  def testInputWhenStep1SmallCn(self):
    """Test Input()."""
    n = 123
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.ba.AuthFail().AndReturn(None)
    self.mox.ReplayAll()
    self.ba.Input(n=n)
    self.mox.VerifyAll()

  def testInputWhenStep1Success(self):
    """Test Input()."""
    n = base.MIN_VALUE_CN + 1
    cn = int(n)
    sn = cn + 1
    m = 'msg cn sn '
    sig = 'sig'
    sig_b64 = 'sigb64'

    self.mox.StubOutWithMock(self.ba, 'Nonce')
    self.mox.StubOutWithMock(self.ba, '_AssembleMessage')
    self.mox.StubOutWithMock(self.ba, 'Sign')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64encode')
    self.mox.StubOutWithMock(self.ba, '_AddOutput')
    self.mox.StubOutWithMock(self.ba, 'SessionSetCnSn')

    self.ba.Nonce().AndReturn(sn)
    self.ba._AssembleMessage(str(cn), str(sn)).AndReturn(m)
    self.ba.Sign(m).AndReturn(sig)
    base.base64.urlsafe_b64encode(sig).AndReturn(sig_b64)
    self.ba._AssembleMessage(m, sig_b64).AndReturn(m)
    self.ba._AddOutput(m)
    self.ba.SessionSetCnSn(cn, sn)

    self.mox.ReplayAll()
    self.ba.Input(n=n)
    self.mox.VerifyAll()

  def testInputStep2WhenSplitMessageFail(self):
    """Test Input()."""
    m = 'msg'
    s = 'b64sig'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.ba._SplitMessage(m, 3).AndRaise(base.MessageError)
    self.ba.AuthFail()

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenBase64DecodeSigFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndRaise(TypeError)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenBase64DecodeCertFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndRaise(TypeError)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenLoadOtherCertFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndRaise(ValueError)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenGetPublicKeyFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(None)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenCheckAllFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndRaise(base.x509.Error)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenVerifyCertSignedByCAFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    uuid = 'subjectcn'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndReturn(None)
    mock_client_cert.GetSubject().AndReturn(uuid)
    self.ba.VerifyCertSignedByCA(mock_client_cert).AndReturn(False)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenVerifyDataSignedWithCertFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    uuid = 'subjectcn'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndReturn(None)
    mock_client_cert.GetSubject().AndReturn(uuid)
    self.ba.VerifyCertSignedByCA(mock_client_cert).AndReturn(True)
    self.ba.VerifyDataSignedWithCert(m, s, mock_client_cert).AndReturn(False)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenVerifyDataSignedWithCertException(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    uuid = 'subjectcn'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndReturn(None)
    mock_client_cert.GetSubject().AndReturn(uuid)
    self.ba.VerifyCertSignedByCA(mock_client_cert).AndReturn(True)
    self.ba.VerifyDataSignedWithCert(
        m, s, mock_client_cert).AndRaise(base.CryptoError)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenSessionVerifyKnownCnSnFails(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    uuid = 'subjectcn'
    mock_client_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')
    self.mox.StubOutWithMock(self.ba, 'SessionVerifyKnownCnSn')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndReturn(None)
    mock_client_cert.GetSubject().AndReturn(uuid)
    self.ba.VerifyCertSignedByCA(mock_client_cert).AndReturn(True)
    self.ba.VerifyDataSignedWithCert(m, s, mock_client_cert).AndReturn(True)
    self.ba.SessionVerifyKnownCnSn(cn, sn).AndReturn(False)
    self.ba.AuthFail()
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.mox.VerifyAll()

  def testInputStep2WhenSuccess(self):
    """Test Input()."""
    m = 'c cn sn'
    s = 'b64sig'
    c = 'cert'
    cn = '12345'
    sn = '12345'
    uuid = 'subjectcn'
    mock_client_cert = self.mox.CreateMockAnything()
    token = 'token1234'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')
    self.mox.StubOutWithMock(self.ba, 'SessionVerifyKnownCnSn')
    self.mox.StubOutWithMock(self.ba, 'SessionCreateAuthToken')
    self.mox.StubOutWithMock(self.ba, '_AddOutput')

    self.ba._SplitMessage(m, 3).AndReturn([c, cn, sn])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    base.base64.urlsafe_b64decode(c).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_client_cert)
    mock_client_cert.GetPublicKey().AndReturn(True)
    mock_client_cert.SetRequiredIssuer(self.ba._required_issuer)
    mock_client_cert.CheckAll().AndReturn(None)
    mock_client_cert.GetSubject().AndReturn(uuid)
    self.ba.VerifyCertSignedByCA(mock_client_cert).AndReturn(True)
    self.ba.VerifyDataSignedWithCert(m, s, mock_client_cert).AndReturn(True)
    self.ba.SessionVerifyKnownCnSn(cn, sn).AndReturn(True)
    self.ba.SessionCreateAuthToken(uuid).AndReturn(token)
    self.ba._AddOutput(token).AndReturn(None)
    self.ba.SessionDelCn(cn)

    self.mox.ReplayAll()
    self.ba.Input(m=m, s=s)
    self.assertEqual(self.ba._auth_state, base.AuthState.OK)
    self.mox.VerifyAll()

  def testInputWhenArgumentFailures(self):
    """Test Input()."""
    self.mox.ReplayAll()
    self.assertRaises(ValueError, self.ba.Input, n=1, m=1)
    self.assertRaises(ValueError, self.ba.Input, m=1)
    self.mox.VerifyAll()


class Auth1ClientTest(AuthTestingBase):
  """Test for base.Auth1Client class."""

  def GetTestClass(self):
    return base.Auth1Client()

  def testInit(self):
    """Test __init__()."""
    self.assertEqual(self.ba._key, None)

  def testGetSessionClass(self):
    """Test GetSessionClass()."""
    self.assertEqual(self.ba.GetSessionClass(), base.Auth1ClientSession)

  def testInputWhenStage0(self):
    """Test Input()."""
    nonce = 1111111111111111111111111
    cn = str(nonce)

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, 'Nonce')
    self.mox.StubOutWithMock(self.ba, '_AddOutput')
    self.ba._session = self.mox.CreateMockAnything()

    self.ba.ResetState().AndReturn(None)
    self.ba.Nonce().AndReturn(nonce)
    self.ba._AddOutput(str(nonce))
    self.ba._session.Set('cn', cn)

    self.mox.ReplayAll()
    self.ba.Input()
    self.mox.VerifyAll()

  def testInputWhenStage1SplitMessageFails(self):
    """Test Input()."""
    m = 'msg'

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndRaise(base.MessageError)
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError('SplitMessage MessageError ()').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1Base64DecodeFails(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndRaise(TypeError)
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError('Invalid s parameter b64 format ()').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1LoadOtherCertUnknownCA(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'
    mock_server_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndReturn(
        mock_server_cert)
    self.ba.VerifyCertSignedByCA(mock_server_cert).AndReturn(False)
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError('Server cert is not signed by known CA').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1LoadOtherCertFails(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'
    mock_server_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndRaise(ValueError('a'))
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError('Server cert load error: a').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1SessionCnFails(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'
    mock_server_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndReturn(
        mock_server_cert)
    self.ba.VerifyCertSignedByCA(mock_server_cert).AndReturn(True)
    self.ba._session.Get('cn').AndReturn('not-%s' % cn)
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError(
        'Server supplied Cn does not match our Cn').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1VerifyDataSignedWithCertFails(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'
    tmp_m = 'cn sn'
    mock_server_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, '_AssembleMessage')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndReturn(
        mock_server_cert)
    self.ba.VerifyCertSignedByCA(mock_server_cert).AndReturn(True)
    self.ba._session.Get('cn').AndReturn(cn)
    self.ba._AssembleMessage(cn, sn).AndReturn(tmp_m)
    self.ba.VerifyDataSignedWithCert(
        tmp_m, s, mock_server_cert).AndReturn(False)

    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba._AddError(
        'Sn is not signed by server cert').AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage1Success(self):
    """Test Input()."""
    m = 'cn sn s'
    cn = 'cn'
    sn = 'sn'
    s = 's'
    tmp_m = 'cn sn'
    cert_str = 'server cert str'
    c = 'base64 server cert'
    mock_server_cert = self.mox.CreateMockAnything()
    out_m = 'c cn sn'
    sig = 'sig of out_m'

    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.mox.StubOutWithMock(self.ba, '_AddError')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, '_AssembleMessage')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64encode')
    self.mox.StubOutWithMock(self.ba, 'Sign')

    self.ba.ResetState().AndReturn(None)
    self.ba._SplitMessage(m, 3).AndReturn([cn, sn, s])
    base.base64.urlsafe_b64decode(s).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndReturn(
        mock_server_cert)
    self.ba.VerifyCertSignedByCA(mock_server_cert).AndReturn(True)
    self.ba._session.Get('cn').AndReturn(cn)
    self.ba._AssembleMessage(cn, sn).AndReturn(tmp_m)
    self.ba.VerifyDataSignedWithCert(
        tmp_m, s, mock_server_cert).AndReturn(True)
    self.ba._cert_str = cert_str
    base.base64.urlsafe_b64encode(self.ba._cert_str).AndReturn(c)
    self.ba._AssembleMessage(c, cn, sn).AndReturn(out_m)
    self.ba.Sign(out_m).AndReturn(sig)
    base.base64.urlsafe_b64encode(sig).AndReturn(sig)
    self.ba._AddOutput({'m': out_m, 's': sig})

    self.mox.ReplayAll()
    self.ba.Input(m=m)
    self.mox.VerifyAll()

  def testInputWhenStage3NotTokenFails(self):
    """Test Input()."""
    self.mox.StubOutWithMock(self.ba, 'AuthFail')
    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.ba.ResetState().AndReturn(None)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(t='not-%s' % base.Auth1.TOKEN)
    self.assertNotEqual(self.ba._auth_state, base.AuthState.OK)
    self.mox.VerifyAll()

  def testInputWhenStage3Success(self):
    """Test Input()."""
    self.ba._session = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.ba, 'ResetState')
    self.ba.ResetState().AndReturn(None)
    self.ba._session.DeleteById('cn').AndReturn(None)
    self.ba.ResetState().AndReturn(None)

    self.mox.ReplayAll()
    self.ba.Input(t=base.Auth1.TOKEN)
    self.assertEqual(self.ba._auth_state, base.AuthState.OK)
    self.mox.VerifyAll()

  def testInputWhenArgumentFailures(self):
    """Test Input()."""
    self.mox.ReplayAll()
    self.assertRaises(ValueError, self.ba.Input, m=1, t=1)
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
