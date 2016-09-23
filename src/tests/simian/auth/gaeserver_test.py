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
"""gaeserver module tests."""

import datetime
import logging
import os
logging.basicConfig(filename='/dev/null')

import tests.appenginesdk


import mox
import stubout

from google.apputils import app
from google.apputils import basetest

from simian import auth
from simian.auth import gaeserver
from simian.mac import models
from tests.simian.mac.common import test


class GaeserverModuleTest(mox.MoxTestBase):
  """Test gaeserver module-level functions."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testLevelValues(self):
    """Test LEVEL_* constants."""
    self.assertEqual(gaeserver.LEVEL_BASE, 0)
    self.assertEqual(gaeserver.LEVEL_ADMIN, 5)
    self.assertEqual(gaeserver.LEVEL_UPLOADPKG, 5)

  def testDoMunkiAuth(self):
    """Test DoMunkiAuth()."""
    level = 123
    cookie_str = 'foo=bar'
    token = 'cookie value for auth.AUTH_TOKEN_COOKIE'
    uuid = 'session uuid'
    mock_valobj = self.mox.CreateMockAnything()
    mock_valobj.value = token
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = 'session uuid'

    mock_environ = self.mox.CreateMockAnything()
    mock_cookie = self.mox.CreateMockAnything()
    mock_auth1 = self.mox.CreateMockAnything()

    self.stubs.Set(gaeserver.os, 'environ', mock_environ)
    self.mox.StubOutWithMock(gaeserver.Cookie, 'SimpleCookie', True)
    self.mox.StubOutWithMock(gaeserver, 'AuthSimianServer', True)

    # 0: fake_noauth=True, nothing to mock

    # test 1: missing cookie
    mock_environ.get('HTTP_COOKIE', None).AndReturn(None)

    # test 2: cookie is malformed
    mock_environ.get('HTTP_COOKIE', None).AndReturn(cookie_str)
    gaeserver.Cookie.SimpleCookie().AndReturn(mock_cookie)
    mock_cookie.load(cookie_str).AndRaise(TypeError)

    # test 3: cookie exists, but isn't ours
    mock_environ.get('HTTP_COOKIE', None).AndReturn(cookie_str)
    gaeserver.Cookie.SimpleCookie().AndReturn(mock_cookie)
    mock_cookie.load(cookie_str).AndRaise(gaeserver.Cookie.CookieError)

    # test 4: cookie exists, is ours, but token isn't authenticated
    mock_environ.get('HTTP_COOKIE', None).AndReturn(cookie_str)
    gaeserver.Cookie.SimpleCookie().AndReturn(mock_cookie)
    mock_cookie.load(cookie_str).AndReturn(None)
    mock_cookie.__contains__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(False)

    # test 5: GetSessionIfAuthOK() returns false, bad token
    mock_environ.get('HTTP_COOKIE', None).AndReturn(cookie_str)
    gaeserver.Cookie.SimpleCookie().AndReturn(mock_cookie)
    mock_cookie.load(cookie_str).AndReturn(None)
    mock_cookie.__contains__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(True)
    mock_cookie.__getitem__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(mock_valobj)
    gaeserver.AuthSimianServer().AndReturn(mock_auth1)
    mock_cookie.__getitem__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(mock_valobj)
    mock_auth1.GetSessionIfAuthOK(token, gaeserver.LEVEL_BASE).AndRaise(
        gaeserver.base.AuthSessionError)

    # 6: test all success!
    mock_environ.get('HTTP_COOKIE', None).AndReturn(cookie_str)
    gaeserver.Cookie.SimpleCookie().AndReturn(mock_cookie)
    mock_cookie.load(cookie_str).AndReturn(None)
    mock_cookie.__contains__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(True)
    mock_cookie.__getitem__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(mock_valobj)
    gaeserver.AuthSimianServer().AndReturn(mock_auth1)
    mock_cookie.__getitem__(
        gaeserver.auth.AUTH_TOKEN_COOKIE).AndReturn(mock_valobj)
    mock_auth1.GetSessionIfAuthOK(token, level).AndReturn(mock_session)

    self.mox.ReplayAll()
    self.assertRaises(
        gaeserver.NotAuthenticated,
        gaeserver.DoMunkiAuth, fake_noauth=True)  # 0
    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)  # 1
    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)  # 2
    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)  # 3
    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)  # 4
    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)  # 5
    session = gaeserver.DoMunkiAuth(require_level=level)  # 6
    self.assertEqual(uuid, session.uuid)  # 6
    self.mox.VerifyAll()

  def testLogoutSession(self):
    """Test LogoutSession."""
    session = 'foo'
    self.mox.StubOutWithMock(gaeserver, 'AuthSessionSimianServer', True)
    mock_session = self.mox.CreateMockAnything()
    gaeserver.AuthSessionSimianServer().AndReturn(mock_session)
    mock_session.Delete(session).AndReturn(None)
    self.mox.ReplayAll()
    gaeserver.LogoutSession(session)
    self.mox.VerifyAll()


class DatastoreModelTest(mox.MoxTestBase):
  """Base class for all Datastore session tests that mock GetModelClass()."""

  class _LocalTestClass(object):
    MAGIC = 1

  def _MockModelClass(self, cls=None):
    if cls is None:
      cls = self._LocalTestClass
    self.stubs.Set(
        gaeserver.Auth1ServerDatastoreSession, 'GetModelClass',
        self.mox.CreateMockAnything())
    gaeserver.Auth1ServerDatastoreSession.GetModelClass().AndReturn(cls)

  def _StubGetModelClass(self, cls=None):
    if cls is None:
      cls = self._LocalTestClass
    self.stubs.Set(
        gaeserver.Auth1ServerDatastoreSession, 'GetModelClass',
        lambda x: cls)


class Auth1ServerDatastoreSessionTest(DatastoreModelTest):
  """Test Auth1ServerDatastoreSession class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _StubDatetime(self):
    self.stubs.Set(
        gaeserver.datetime, 'datetime',
        self.mox.CreateMockAnything())
    self.stubs.Set(
        gaeserver.datetime, 'timedelta',
        self.mox.CreateMockAnything())

  def _MockGetConfig(self, ads, config):
    """Mock _GetConfig() on instance ads and return config."""
    if not hasattr(ads, '_set_mockgetconfig'):
      self.mox.StubOutWithMock(ads, '_GetConfig')
      ads._set_mockgetconfig = True
    ads._GetConfig().AndReturn(config)

  def _GetAds(self):
    ads = gaeserver.Auth1ServerDatastoreSession()
    ads.model = self.mox.CreateMockAnything()
    return ads

  def testGetModelClass(self):
    """Test GetModelClass()."""
    try:
      gaeserver.Auth1ServerDatastoreSession.GetModelClass()
      self.fail('GetModelClass() did not raise NotImplementedError')
    except NotImplementedError:
      pass

  def testInit(self):
    """Test __init__()."""
    self._MockModelClass()

    self.mox.ReplayAll()
    ads = gaeserver.Auth1ServerDatastoreSession()
    self.assertEqual(ads.model.MAGIC, 1)
    self.mox.VerifyAll()

  def testGetConfig(self):
    """Test _GetConfig()."""
    self._MockModelClass()
    self.mox.StubOutWithMock(gaeserver.datastore, 'CreateRPC')
    config = 'config'
    gaeserver.datastore.CreateRPC(
        deadline=gaeserver.DATASTORE_RPC_DEADLINE).AndReturn(config)

    self.mox.ReplayAll()
    ads = self._GetAds()
    self.assertEqual(config, ads._GetConfig())
    self.mox.VerifyAll()

  def testSet(self):
    """Test Set()."""
    sid = '123'
    data = 'tea'
    now = 10

    self._StubGetModelClass()

    ads = self._GetAds()
    self.mox.StubOutWithMock(ads, '_Now')

    config = 'config'
    self.mox.StubOutWithMock(gaeserver.datastore, 'CreateRPC')
    gaeserver.datastore.CreateRPC(deadline=ads.deadline).AndReturn(config)

    session = self.mox.CreateMockAnything()
    session.put(rpc=config).AndReturn(None)

    ads.model(key_name=sid).AndReturn(session)
    ads._Now().AndReturn(now)

    self.mox.ReplayAll()
    ads.Set(sid, data)
    self.assertEqual(session.data, data)
    self.assertEqual(session.mtime, now)
    self.mox.VerifyAll()

  def testGetWithoutExpiry(self):
    """Test Get() where the session has not expired."""
    sid = '123'
    data = 'data'

    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')
    self.mox.StubOutWithMock(ads, 'ExpireOne')

    session = self.mox.CreateMockAnything()
    session.data = data
    session.mtime = 1

    ads.model.get_by_key_name(sid, rpc='config').AndReturn(session)
    ads.ExpireOne(session).AndReturn(False)

    self.mox.ReplayAll()
    self.assertEqual(data, ads.Get(sid))
    self.mox.VerifyAll()

  def testGetWithExpiry(self):
    """Test Get() where the session has expired."""
    sid = '123'
    data = 'data'

    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')
    self.mox.StubOutWithMock(ads, 'ExpireOne')

    session = self.mox.CreateMockAnything()
    session.data = data
    session.mtime = 1

    ads.model.get_by_key_name(sid, rpc='config').AndReturn(session)
    ads.ExpireOne(session).AndReturn(True)

    self.mox.ReplayAll()
    self.assertEqual(None, ads.Get(sid))
    self.mox.VerifyAll()

  def testGetNoExistSession(self):
    """Test Get() where the session doesn't exist."""
    sid = '123'
    data = 'data'

    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')

    ads.model.get_by_key_name(sid, rpc='config').AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(None, ads.Get(sid))
    self.mox.VerifyAll()

  def testDeleteById(self):
    """Test DeleteById() were it succeeds."""
    sid = '123'
    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')
    self._MockGetConfig(ads, 'config2')

    session = self.mox.CreateMockAnything()
    session.delete(rpc='config2').AndReturn(None)

    ads.model.get_by_key_name(sid, rpc='config').AndReturn(session)

    self.mox.ReplayAll()
    ads.DeleteById(sid)
    self.mox.VerifyAll()

  def testDelNoExist(self):
    """Test DeleteById() were the session does not exist."""
    sid = '123'
    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')

    ads.model.get_by_key_name(sid, rpc='config').AndReturn(None)

    self.mox.ReplayAll()
    ads.DeleteById(sid)
    self.mox.VerifyAll()

  def testDelete(self):
    """Test Delete()."""
    self._StubGetModelClass()

    ads = self._GetAds()
    self._MockGetConfig(ads, 'config')

    session = self.mox.CreateMockAnything()
    session.delete(rpc='config').AndReturn(None)

    self.mox.ReplayAll()
    ads.Delete(session)
    self.mox.VerifyAll()

  def testMtime(self):
    """Test _Mtime()."""
    session = self.mox.CreateMockAnything()
    session.mtime = 12345

    self._StubGetModelClass()

    ads = self._GetAds()
    self.mox.ReplayAll()
    self.assertEqual(12345, ads._Mtime(session))
    self.mox.VerifyAll()


class Auth1ServerDatastoreMemcacheSessionTest(DatastoreModelTest):
  """Test Auth1ServerDatastoreMemcacheSession class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self._StubGetModelClass()
    self.ams = gaeserver.Auth1ServerDatastoreMemcacheSession()
    self._mocked = {}
    self.sid = '12345'

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _MockMemcache(self, method_name, *args, **kwargs):
    """Mock a method call to memcache.

    Args:
      method_name: str, like 'get'
      *args: list, arguments to supply
      **kwargs: dict, arguments to supply
    Returns:
      mocked function handler ready to apply action to (e.g. .AndReturn())
    """
    if not 'memcache' in self._mocked:
      self.stubs.Set(
          gaeserver, 'memcache', self.mox.CreateMock(gaeserver.memcache))
      self._mocked['memcache'] = True
    return getattr(gaeserver.memcache, method_name)(*args, **kwargs)

  def _MockSuper(self, method_name, *args, **kwargs):
    """Mock a method in the super class of the class being tested.

    Args:
      method_name: str, like '_Get'
      *args: list, arguments to supply
      **kwargs: dict, arguments to supply
    Returns:
      mocked function handler ready to apply action to (e.g. .AndReturn())
    """
    parent_class = self.ams.__class__.__bases__[0]
    if not 'super_%s' % method_name in self._mocked:
      self.stubs.Set(
          parent_class, method_name,
          self.mox.CreateMockAnything())
      self._mocked['super_%s' % method_name] = True
    return getattr(parent_class, method_name)(*args, **kwargs)

  def _GetMockSession(self, sid=None):
    """Create and return a mock session object."""
    if sid is None:
      sid = self.sid
    session = self.mox.CreateMockAnything()
    key = self.mox.CreateMockAnything()
    name = self.mox.CreateMockAnything()
    session.key().AndReturn(key)
    key.name().AndReturn(sid)
    return session

  def _Key(self, sid):
    return '%s%s' % (self.ams.prefix, sid)

  def testInit(self):
    """Test __init__()."""
    self.assertEqual(self.ams.prefix, 'a1sd_')
    self.assertTrue(self.ams.ttl <= 120)
    self.assertTrue(hasattr(self.ams, 'model')) # from super()

  def _testCallSuperWithDeferSuccess(self):
    """Test the _CallSuperWithDefer() method."""
    method_name = '_FooMethod'
    args = ['foo', 'bar']
    kwargs = {'foo': 'bar', 'bar': 'foo'}

    mock_method = self.mox.CreateMockAnything()
    setattr(gaeserver.Auth1ServerDatastoreSession, method_name, mock_method)
    mock_method(*args, **kwargs).AndReturn(True)

    self.mox.ReplayAll()
    self.ams._CallSuperWithDefer(method_name, *args, **kwargs)
    self.mox.VerifyAll()

  def _testCallSuperWithDeferFailureDeferred(self):
    """Test the _CallSuperWithDefer() method where deferred is needed."""
    method_name = '_FooMethod'
    args = ['foo', 'bar']
    kwargs = {'foo': 'bar', 'bar': 'foo'}
    self.mox.StubOutWithMock(gaeserver.time, 'time')
    self.mox.StubOutWithMock(gaeserver.deferred, 'defer')

    mock_method = self.mox.CreateMockAnything()
    setattr(gaeserver.Auth1ServerDatastoreSession, method_name, mock_method)
    mock_method(*args, **kwargs).AndRaise(gaeserver.db.Error)
    gaeserver.time.time().AndReturn(1)
    deferred_name = 'a1sdms-1000-%s' % method_name.replace('_', '')
    gaeserver.deferred.defer(mock_method, _name=deferred_name, *args, **kwargs)

    self.mox.ReplayAll()
    self.ams._CallSuperWithDefer(method_name, *args, **kwargs)
    self.mox.VerifyAll()

  def testGetWhenCacheHit(self):
    """Test _Get()."""
    sid = self.sid
    data = 'data we want to be cached'
    self._MockMemcache(
        'get', self._Key(sid)).AndReturn(data)

    self.mox.ReplayAll()
    self.assertEqual(self.ams._Get(sid), data)
    self.mox.VerifyAll()

  def testGetWhenCacheMiss(self):
    """Test _Get()."""
    sid = self.sid
    data = 'data we got from datastore'
    self._MockMemcache(
        'get', self._Key(sid)).AndReturn(None)
    self._MockSuper('_Get', sid).AndReturn(data)

    self.mox.ReplayAll()
    self.assertEqual(self.ams._Get(sid), data)
    self.mox.VerifyAll()

  def testPut(self):
    """Test _Put()."""
    session = self._GetMockSession()
    self._MockMemcache(
        'set', self._Key(self.sid),
        value=session,
        time=self.ams.ttl).AndReturn(None)
    self._MockSuper('_Put', session).AndReturn(None)

    self.mox.ReplayAll()
    self.ams._Put(session)
    self.mox.VerifyAll()

  def testDeleteById(self):
    """Test DeleteById()."""
    sid = self.sid
    self._MockMemcache(
        'delete', self._Key(sid)).AndReturn(None)
    self._MockSuper(
        'DeleteById', sid).AndReturn(None)

    self.mox.ReplayAll()
    self.ams.DeleteById(sid)
    self.mox.VerifyAll()

  def testDelete(self):
    """Test Delete()."""
    session = self._GetMockSession()
    self._MockMemcache(
        'delete', self._Key(self.sid)).AndReturn(None)
    self._MockSuper('Delete', session).AndReturn(None)

    self.mox.ReplayAll()
    self.ams.Delete(session)
    self.mox.VerifyAll()


class AuthSessionSimianServer(mox.MoxTestBase, test.AppengineTest):
  """Test AuthSessionSimianServer class."""

  def setUp(self):
    super(test.AppengineTest, self).setUp()

    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.asps = gaeserver.AuthSessionSimianServer()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

    super(test.AppengineTest, self).tearDown()

  def _StubDatetime(self):
    self.stubs.Set(
        gaeserver.datetime, 'datetime',
        self.mox.CreateMockAnything())
    self.stubs.Set(
        gaeserver.datetime, 'timedelta',
        self.mox.CreateMockAnything())

  def testGetModelClass(self):
    self.assertTrue(
        (gaeserver.AuthSessionSimianServer.GetModelClass() is
        gaeserver.models.AuthSession))

  def _TestExpireOneSession(self, session_prefix, session_age_seconds):
    """Test ExpireOne() with a token session item.

    Args:
      session_prefix: str, like 'foo_'
      session_age_seconds: int, allowable session age data seconds
    """
    session = models.AuthSession(
        mtime=datetime.datetime.utcnow() - datetime.timedelta(
            seconds=session_age_seconds),
        key_name=session_prefix + '123')
    session.put()

    asd = gaeserver.AuthSessionSimianServer()
    self.assertEqual(True, asd.ExpireOne(session))

    self.assertEqual(0, len(models.AuthSession.all().fetch(None)))

  def testExpireOneToken(self):
    """Test ExpireOne() on a token session item."""
    self._TestExpireOneSession(
        self.asps.SESSION_TYPE_PREFIX_TOKEN,
        gaeserver.base.AGE_TOKEN_SECONDS)

  def testExpireOneCn(self):
    """Test ExpireOne() on a cn session item."""
    self._TestExpireOneSession(
        self.asps.SESSION_TYPE_PREFIX_CN,
        gaeserver.base.AGE_CN_SECONDS)


class AuthSimianServer(mox.MoxTestBase, test.AppengineTest):
  """Test AuthSimianServer class."""

  def setUp(self):
    super(test.AppengineTest, self).setUp()

    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.aps = gaeserver.AuthSimianServer()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

    super(test.AppengineTest, self).tearDown()

  def testInit(self):
    """Test __init__()."""

  def testLoadCaParameters(self):
    """Test LoadCaParameters()."""
    self.mox.StubOutWithMock(gaeserver.util, 'GetCaParameters')
    self.mox.StubOutWithMock(self.aps, 'LoadSelfKey')

    settings = {}

    ca_params = self.mox.CreateMockAnything()
    ca_params.ca_public_cert_pem = 'ca'
    ca_params.server_public_cert_pem = 'spub'
    ca_params.server_private_key_pem = 'spriv'
    ca_params.required_issuer = 'ri'

    gaeserver.util.GetCaParameters(
        settings, None).AndReturn(ca_params)
    self.aps.LoadSelfKey('spriv').AndReturn(None)

    self.mox.ReplayAll()
    self.aps.LoadCaParameters(settings)
    self.assertEqual(self.aps._ca_pem, 'ca')
    self.assertEqual(self.aps._server_cert_pem, 'spub')
    self.assertEqual(self.aps._required_issuer, 'ri')
    self.mox.VerifyAll()

  def testLoadCaParametersWhenValueError(self):
    """Test LoadCaParameters()."""
    self.mox.StubOutWithMock(gaeserver.util, 'GetCaParameters')
    self.mox.StubOutWithMock(self.aps, 'LoadSelfKey')

    settings = {}

    ca_params = self.mox.CreateMockAnything()
    ca_params.ca_public_cert_pem = 'ca'
    ca_params.server_public_cert_pem = 'spub'
    ca_params.server_private_key_pem = 'spriv'
    ca_params.required_issuer = 'ri'

    gaeserver.util.GetCaParameters(
        settings, None).AndReturn(ca_params)
    self.aps.LoadSelfKey('spriv').AndRaise(ValueError)

    self.mox.ReplayAll()
    self.assertRaises(
        gaeserver.CaParametersError, self.aps.LoadCaParameters, settings)
    self.mox.VerifyAll()

  def testLoadCaParametersWhenError(self):
    """Test LoadCaParameters()."""
    self.mox.StubOutWithMock(gaeserver.util, 'GetCaParameters')
    self.mox.StubOutWithMock(self.aps, 'LoadSelfKey')

    settings = {}

    ca_params = self.mox.CreateMockAnything()
    ca_params.ca_public_cert_pem = 'ca'
    ca_params.server_public_cert_pem = 'spub'
    ca_params.server_private_key_pem = 'spriv'
    ca_params.required_issuer = 'ri'

    gaeserver.util.GetCaParameters(
        settings, None).AndRaise(gaeserver.util.CaParametersError)

    self.mox.ReplayAll()
    self.assertRaises(
        gaeserver.CaParametersError, self.aps.LoadCaParameters, settings)
    self.mox.VerifyAll()

  def testGetSessionClass(self):
    """Test GetSessionClass()."""
    self.assertTrue(
        self.aps.GetSessionClass() is gaeserver.AuthSessionSimianServer)

  def testAuthLevel(self):
    auth1 = gaeserver.AuthSimianServer()
    token = auth1.SessionCreateUserAuthToken(
        'long_uuid', level=gaeserver.LEVEL_APPLESUS)

    os.environ['HTTP_COOKIE'] = '%s=%s' % (auth.AUTH_TOKEN_COOKIE, token)

    self.assertRaises(gaeserver.NotAuthenticated, gaeserver.DoMunkiAuth)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
