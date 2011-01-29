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

"""pkgsinfo module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
import mox
import stubout
from google.apputils import basetest
from simian.mac.munki.handlers import pkgsinfo
from simian.mac.common import test


class MunkiPackageInfoPlistStrictTest(mox.MoxTestBase):
  """Test MunkiPackageInfoPlistStrict class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.mpl = pkgsinfo.MunkiPackageInfoPlistStrict()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testInit(self):
    """Tests that __init__ added the package exists validation hook."""
    self.assertTrue(
        self.mpl.ValidatePackageExists in self.mpl._validation_hooks)

  def testValidatePackageExists(self):
    """Tests the ValidatePackageExists() method."""
    package = 'package_location'
    self.mpl._plist = {'installer_item_location': package}
    self.stubs.Set(
        pkgsinfo.pkgs, 'PackageExists', self.mox.CreateMockAnything())
    pkgsinfo.pkgs.PackageExists(package).AndReturn(True)
    pkgsinfo.pkgs.PackageExists(package).AndReturn(False)

    self.mox.ReplayAll()
    self.assertEqual(None, self.mpl.ValidatePackageExists())
    self.assertRaises(
        pkgsinfo.PackageDoesNotExistError, self.mpl.ValidatePackageExists)
    self.mox.VerifyAll()


class PackagesInfoTest(test.RequestHandlerTest):
  """Test PackagesInfo webapp request handler."""

  def GetTestClassInstance(self):
    return pkgsinfo.PackagesInfo()

  def GetTestClassModule(self):
    return pkgsinfo

  def _MockObtainLock(self, lock, obtain=True, timeout=None):
    """Mock ObtainLock().

    Args:
      lock: str, lock name
      obtain: bool, default True, whether to obtain it or not
      timeout: int, timeout value to ObtainLock with
    """
    if not hasattr(self, '_mock_obtainlock'):
      self.mox.StubOutWithMock(pkgsinfo.common, 'ObtainLock')
      self._mock_obtainlock = True
    if timeout is not None:
      pkgsinfo.common.ObtainLock(lock, timeout=timeout).AndReturn(obtain)
    else:
      pkgsinfo.common.ObtainLock(lock).AndReturn(obtain)

  def _MockReleaseLock(self, lock):
    """Mock ReleaseLock().

    Args:
      lock: str, lock name
    """
    if not hasattr(self, '_mock_releaselock'):
      self.mox.StubOutWithMock(pkgsinfo.common, 'ReleaseLock')
      self._mock_releaselock = True
    pkgsinfo.common.ReleaseLock(lock).AndReturn(None)

  def testHash(self):
    """Test _Hash()."""
    self.stubs.Set(
      pkgsinfo.hashlib, 'sha256',
      self.mox.CreateMock(pkgsinfo.hashlib.sha256))
    s = 'foo'
    h = self.mox.CreateMockAnything()
    h.hexdigest().AndReturn('hexfoo')
    pkgsinfo.hashlib.sha256(s).AndReturn(h)
    self.mox.ReplayAll()
    self.assertEqual(self.c._Hash(s), 'hexfoo')
    self.mox.VerifyAll()

  def testGetSuccess(self):
    """Test get() with success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'plist'
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(pkginfo.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetSuccessWhenHash(self):
    """Test get() with success when hash header is requested."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    self.request.get('hash').AndReturn('1')
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'plist'
    self.mox.StubOutWithMock(self.c, '_Hash')
    self.c._Hash(pkginfo.plist).AndReturn('hash')
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.headers['X-Pkgsinfo-Hash'] = 'hash'
    self.response.out.write(pkginfo.plist).AndReturn(None)
    self._MockReleaseLock('pkgsinfo_%s' % filename)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetSuccessWhenHashLockFail(self):
    """Test get() with success when hash header is requested and lock fails."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    self.request.get('hash').AndReturn('1')
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0, obtain=False)
    self.response.set_status(403, 'Could not lock pkgsinfo')

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetFailAuth(self):
    """Test get() with auth failure."""
    self.MockDoAnyAuth(fail=True)

    self.mox.ReplayAll()
    self.assertRaises(
        pkgsinfo.gaeserver.base.NotAuthenticated,
        self.c.get,
        'x')
    self.mox.VerifyAll()

  def testGetFailPackageNoExist(self):
    """Test get() with failure."""
    filename = 'pkgnamenotfound.dmg'
    self.MockDoAnyAuth()
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(None)
    self.request.get('hash').AndReturn(None)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testPutFailAuth(self):
    """Test put() with auth failure."""
    self.MockDoMunkiAuth(
        fail=True, require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)

    self.mox.ReplayAll()
    self.assertRaises(
        pkgsinfo.gaeserver.NotAuthenticated,
        self.c.put,
        'x')
    self.mox.VerifyAll()

  def testGetSuccess(self):
    """Test get() pkg list with success."""
    filename = None
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['stable', 'testing']
    mock_pkg = self.mox.CreateMockAnything()
    mock_pkg_properties  = ['name', 'foo']
    mock_pkg.name = 'fooname'
    mock_pkg.foo = 'foofoo'
    pkgs = [{'name': mock_pkg.name, 'foo': mock_pkg.foo}]

    self.mox.StubOutWithMock(pkgsinfo.plist, 'GetXmlStr')

    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)

    mock_query = self.MockModelStatic('PackageInfo', 'all')
    self.request.get_all('install_types').AndReturn(install_types)
    self.request.get_all('catalogs').AndReturn(catalogs)
    for t in install_types:
      mock_query.filter('install_types =', t)
    for t in catalogs:
      mock_query.filter('catalogs =', t)

    mock_iter = self.mox.CreateMockAnything()
    mock_query.__iter__().AndReturn(mock_iter)
    mock_iter.next().AndReturn(mock_pkg)
    mock_pkg.properties().AndReturn(mock_pkg_properties)
    mock_iter.next().AndRaise(StopIteration)

    self.response.out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    pkgsinfo.plist.GetXmlStr(pkgs).AndReturn('XML')
    self.response.out.write('XML')
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testPutFailInputNotParseable(self):
    """Test put() with input that isn't parseable as a plist."""
    filename = 'pkgname.dmg'
    body = 'junk'
    self.request.body = body

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs').AndReturn('anything')
    self.request.get('manifests').AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.plist.MalformedPlistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(400, 'foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutFailInputMissingFields(self):
    """Test put() with input that isn't parseable as a plist."""
    filename = 'pkgname.dmg'
    body = 'junk'
    self.request.body = body
    parsed_dict = {'missing': 'the required values'}

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs').AndReturn('anything')
    self.request.get('manifests').AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.plist.InvalidPlistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(400, 'foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutFailPackageNoExist(self):
    """Test put() with valid input params, but package does not exist."""
    filename = 'pkgname.dmg'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    self.request.body = body

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs').AndReturn('anything')
    self.request.get('manifests').AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.PackageDoesNotExistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(400, 'foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutOnNonexistentPackageInfo(self):
    """Test put() with valid input params, but non-existent pkginfo."""
    filename = 'pkgname.dmg'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    pkgdict = {'installer_item_location': pkgloc}
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs').AndReturn(','.join(catalogs))
    self.request.get('manifests').AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0)
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(None)

    self.response.set_status(403, 'Only updates supported')
    self._MockReleaseLock('pkgsinfo_%s' % filename)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutSuccess(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    pkgdict = {'installer_item_location': pkgloc}
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs').AndReturn(','.join(catalogs))
    self.request.get('manifests').AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)

    pkginfo.plist = mock_mpl.GetXml().AndReturn(body)
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()
    self._MockReleaseLock('pkgsinfo_%s' % filename)

    self.mox.StubOutWithMock(pkgsinfo.common, 'CreateCatalog')
    for catalog in catalogs:
      pkgsinfo.common.CreateCatalog(catalog, delay=1).AndReturn(None)

    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, body)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.assertEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutSuccessWhenHash(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    pkgdict = {'installer_item_location': pkgloc}
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn('goodhash')
    self.request.get('catalogs').AndReturn(','.join(catalogs))
    self.request.get('manifests').AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    self.mox.StubOutWithMock(self.c, '_Hash')
    pkginfo.plist = mock_mpl.GetXml().AndReturn(body)
    self.c._Hash(pkginfo.plist).AndReturn('goodhash')
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()
    self._MockReleaseLock('pkgsinfo_%s' % filename)

    self.mox.StubOutWithMock(pkgsinfo.common, 'CreateCatalog')
    for catalog in catalogs:
      pkgsinfo.common.CreateCatalog(catalog, delay=1).AndReturn(None)

    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, body)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.assertEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutSuccessWhenHashFail(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    pkgdict = {'installer_item_location': pkgloc}
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']

    self.request.get('hash').AndReturn('goodhash')
    self.request.get('catalogs').AndReturn(','.join(catalogs))
    self.request.get('manifests').AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    self._MockObtainLock('pkgsinfo_%s' % filename, timeout=5.0)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    self.mox.StubOutWithMock(self.c, '_Hash')
    pkginfo.plist = 'foo'
    self.c._Hash(pkginfo.plist).AndReturn('otherhash')
    self.response.set_status(409, 'Update hash does not match').AndReturn(None)
    self._MockReleaseLock('pkgsinfo_%s' % filename)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.mox.VerifyAll()


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()