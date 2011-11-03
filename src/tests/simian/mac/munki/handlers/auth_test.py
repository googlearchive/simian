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

"""auth module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from simian.mac.common import test
from simian.mac.munki.handlers import auth


class AuthModuleTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return auth.Auth()

  def GetTestClassModule(self):
    return auth

  def testGetAuth1Instance(self):
    """Tests GetAuth1Instance()."""
    auth_one = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(auth.gaeserver, 'AuthSimianServer')
    self.mox.StubOutWithMock(auth.gaeserver, 'GetSimianPrivateKey')
    auth.gaeserver.AuthSimianServer().AndReturn(auth_one)
    auth.gaeserver.GetSimianPrivateKey().AndReturn('key')
    auth_one.LoadSelfKey('key')
    self.mox.ReplayAll()
    self.assertEqual(auth_one, self.c.GetAuth1Instance())
    self.mox.VerifyAll()

  def testGetAuth1InstanceFailure(self):
    """Tests GetAuth1Instance() failure."""
    auth_one = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(auth.gaeserver, 'AuthSimianServer')
    self.mox.StubOutWithMock(auth.gaeserver, 'GetSimianPrivateKey')
    auth.gaeserver.AuthSimianServer().AndReturn(auth_one)
    auth.gaeserver.GetSimianPrivateKey().AndRaise(
        auth.gaeserver.ServerCertMissing)
    self.mox.ReplayAll()
    self.assertRaises(
        auth.base.NotAuthenticated, self.c.GetAuth1Instance)
    self.mox.VerifyAll()

  def testIsRemoteIpAddressBlockedWhenEmptyIp(self):
    """Tests _IsRemoteIpAddressBlocked() with empty IP."""
    self.assertEqual(False, self.c._IsRemoteIpAddressBlocked(''))
    self.assertEqual(False, self.c._IsRemoteIpAddressBlocked(None))

  def testIsRemoteIpAddressBlockedWhenNone(self):
    """Tests _IsRemoteIpAddressBlocked() with no blocked IP blocks."""
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = []

    auth.models.KeyValueCache.MemcacheWrappedGet(
        'auth_bad_ip_blocks', 'text_value').AndReturn('serialized')
    auth.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertFalse(self.c._IsRemoteIpAddressBlocked(ip))
    self.mox.VerifyAll()

  def testIsRemoteIpAddressBlockedWhenNone(self):
    """Tests _IsRemoteIpAddressBlocked() with empty blocked IP list."""
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = []

    auth.models.KeyValueCache.MemcacheWrappedGet(
        'auth_bad_ip_blocks', 'text_value').AndReturn('')

    self.mox.ReplayAll()
    self.assertFalse(self.c._IsRemoteIpAddressBlocked(ip))
    self.mox.VerifyAll()

  def testIsRemoteIpAddressBlockedWhenNone(self):
    """Tests _IsRemoteIpAddressBlocked() with unblocked IP."""
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = ['192.168.0.0/16']

    auth.models.KeyValueCache.MemcacheWrappedGet(
        'auth_bad_ip_blocks', 'text_value').AndReturn('serialized')
    auth.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertFalse(self.c._IsRemoteIpAddressBlocked(ip))
    self.mox.VerifyAll()

  def testIsRemoteIpAddressBlockedWhenBlocked(self):
    """Tests _IsRemoteIpAddressBlocked() with a blocked IP."""
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = ['192.168.0.0/16', '1.0.0.0/8']

    auth.models.KeyValueCache.MemcacheWrappedGet(
        'auth_bad_ip_blocks', 'text_value').AndReturn('serialized')
    auth.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertTrue(self.c._IsRemoteIpAddressBlocked(ip))
    self.mox.VerifyAll()

  def testIsRemoteIpAddressBlockedWhenIpv6(self):
    """Tests _IsRemoteIpAddressBlocked() with an ipv6 IP."""
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    ip = '2620:0:1003:1007:216:36ff:feee:f090'
    deserialized = ['192.168.0.0/16', '1.0.0.0/8']

    auth.models.KeyValueCache.MemcacheWrappedGet(
        'auth_bad_ip_blocks', 'text_value').AndReturn('serialized')
    auth.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertFalse(self.c._IsRemoteIpAddressBlocked(ip))
    self.mox.VerifyAll()

  def testGetWithLogout(self):
    """Tests get() with logout."""
    session = 'foosession'
    self.mox.StubOutWithMock(auth.gaeserver, 'LogoutSession')
    self.MockDoMunkiAuth(and_return=session)
    self.request.get('logout').AndReturn(True)
    auth.gaeserver.LogoutSession(session).AndReturn(None)
    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetWithoutLogout(self):
    """Tests get() without logout."""
    self.MockDoMunkiAuth()
    self.request.get('logout').AndReturn(False)
    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def PostSetup(self):
    """Sets up post() tests."""
    self.mox.StubOutWithMock(auth.logging, 'critical')
    self.mox.StubOutWithMock(auth.logging, 'exception')
    mock_auth1 = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(self.c, 'GetAuth1Instance')
    self.c.GetAuth1Instance().AndReturn(mock_auth1)
    self.mox.StubOutWithMock(self.c, '_IsRemoteIpAddressBlocked')
    ip = '0.0.0.0'
    auth.os.environ['REMOTE_ADDR'] = ip
    self.c._IsRemoteIpAddressBlocked(ip).AndReturn(False)
    self.request.get('n', None).AndReturn('n')
    self.request.get('m', None).AndReturn('m')
    self.request.get('s', None).AndReturn('s')
    return mock_auth1

  def testPostWithInvalidParameters(self):
    """Tests post() with invalid parameters."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndRaise(ValueError)
    auth.logging.exception('invalid parameters to auth1.Input()')
    self.mox.ReplayAll()
    self.assertRaises(auth.base.NotAuthenticated, self.c.post)
    self.mox.VerifyAll()

  def testPostNoOutput(self):
    """Tests post() where auth1 output is empty."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndReturn(None)
    mock_auth1.Output().AndReturn(None)
    mock_auth1.AuthState().AndReturn('NO_MATCH_STATE')
    auth.logging.critical('auth_state is %s but no output.', 'NO_MATCH_STATE')
    self.mox.ReplayAll()
    self.assertRaises(auth.base.NotAuthenticated, self.c.post)
    self.mox.VerifyAll()

  def testPostNoMatchingAuthStateWithValidOutput(self):
    """Tests post() where auth1 output is present but not auth state."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndReturn(None)
    mock_auth1.Output().AndReturn('foo')
    mock_auth1.AuthState().AndReturn('does not match any state')
    self.response.out.write('foo')
    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostAuthStateFail(self):
    """Tests post() where auth1 state fail."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndReturn(None)
    mock_auth1.Output().AndReturn('foo')
    mock_auth1.AuthState().AndReturn(auth.gaeserver.base.AuthState.FAIL)
    self.mox.ReplayAll()
    self.assertRaises(auth.base.NotAuthenticated, self.c.post)
    self.mox.VerifyAll()

  def testPostAuthStateOKWithNoOutput(self):
    """Tests post() where auth1 state is OK but no output."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndReturn(None)
    mock_auth1.Output().AndReturn(None)
    mock_auth1.AuthState().AndReturn(auth.gaeserver.base.AuthState.OK)
    auth.logging.critical('Auth is OK but there is no output.')
    self.mox.ReplayAll()
    self.assertRaises(auth.base.NotAuthenticated, self.c.post)
    self.mox.VerifyAll()

  def testPostAuthStateOKWithValidOutput(self):
    """Tests post() where auth1 state is OK and output is valid."""
    mock_auth1 = self.PostSetup()
    mock_auth1.Input(n='n', m='m', s='s').AndReturn(None)
    mock_auth1.Output().AndReturn('foo')
    mock_auth1.AuthState().AndReturn(auth.gaeserver.base.AuthState.OK)
    self.response.headers['Set-Cookie'] = '%s=%s; secure; httponly;' % (
        auth.auth_settings.AUTH_TOKEN_COOKIE, 'foo')
    self.response.out.write(auth.auth_settings.AUTH_TOKEN_COOKIE)
    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()


def main(argv):
  test.main(argv)


if __name__ == '__main__':
  app.run()