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
"""pkgsinfo module tests."""

import httplib
import logging

import mock
import stubout
import mox
import stubout

from simian.mac.common import datastore_locks
from google.apputils import app
from google.apputils import basetest
from simian.mac import models
from tests.simian.mac.common import test
from simian.mac.munki.handlers import pkgsinfo


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

  def testGetSuccessWithFilenameAndNoHash(self):
    """Test get() with success with a filename but no hash."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    self.request.get('hash').AndReturn('')
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'plist'
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(pkginfo.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetSuccessWithFilenameAndHash(self):
    """Test get() with success when hash header is requested."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    self.request.get('hash').AndReturn('1')
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'plist'
    self.mox.StubOutWithMock(self.c, '_Hash')
    self.c._Hash(pkginfo.plist).AndReturn('hash')
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.headers['X-Pkgsinfo-Hash'] = 'hash'
    self.response.out.write(pkginfo.plist).AndReturn(None)

    m = mock.Mock()
    with mock.patch.object(
        datastore_locks, 'DatastoreLock', return_value=m) as lock_mock:
      self.mox.ReplayAll()
      self.c.get(filename_quoted)
      self.mox.VerifyAll()

      lock_mock.assert_called_once_with(models.PACKAGE_LOCK_PREFIX + filename)

    m.assert_has_calls([
        mock.call.Acquire(timeout=30, max_acquire_attempts=5),
        mock.call.Release()])

  def testGetSuccessWhenHashLockFail(self):
    """Test get() with success when hash header is requested and lock fails."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    self.MockDoAnyAuth()
    self.request.get('hash').AndReturn('1')

    datastore_locks.DatastoreLock('pkgsinfo_%s' % filename).Acquire()
    self.response.set_status(httplib.FORBIDDEN).AndReturn(None)
    self.response.out.write('Could not lock pkgsinfo').AndReturn(None)

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
    self.response.set_status(httplib.NOT_FOUND).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testGetFailPackageAndHashNoExist(self):
    """Test get() with failure."""
    filename = 'pkgnamenotfound.dmg'
    self.MockDoAnyAuth()
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(None)
    self.request.get('hash').AndReturn('1')
    self.response.set_status(httplib.NOT_FOUND).AndReturn(None)

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

  def testGetSuccessWithQueryParams(self):
    """Test get() pkg list with success."""
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['stable', 'testing']
    mock_pkg = self.mox.CreateMockAnything()
    mock_pkg_properties = ['name', 'foo']
    mock_pkg.name = 'fooname'
    mock_pkg.foo = 'foofoo'
    pkgs = [{'name': mock_pkg.name, 'foo': mock_pkg.foo}]

    self.mox.StubOutWithMock(pkgsinfo.plist, 'GetXmlStr')

    mock_user = self.mox.CreateMockAnything()
    self.MockDoAnyAuth(and_return=mock_user)
    mock_user.email().AndReturn('foo@example.com')
    self.mox.StubOutWithMock(pkgsinfo.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(pkgsinfo.auth, 'IsSupportUser')
    pkgsinfo.auth.IsAdminUser('foo@example.com').AndReturn(False)
    pkgsinfo.auth.IsSupportUser('foo@example.com').AndReturn(True)

    mock_query = self.MockModelStatic('PackageInfo', 'all')
    self.request.get('filename').AndReturn('')
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
    self.c.get(None)
    self.mox.VerifyAll()

  def testPutFailInputNotParseable(self):
    """Test put() with input that isn't parseable as a plist."""
    filename = 'pkgname.dmg'
    body = 'junk'
    self.request.body = body

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.plist.MalformedPlistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(httplib.BAD_REQUEST).AndReturn(None)
    self.response.out.write('foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutFailInputMissingFields(self):
    """Test put() with input that isn't parseable as a plist."""
    filename = 'pkgname.dmg'
    body = 'junk'
    self.request.body = body

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.plist.InvalidPlistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(httplib.BAD_REQUEST).AndReturn(None)
    self.response.out.write('foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutFailPackageNoExist(self):
    """Test put() with valid input params, but package does not exist."""
    filename = 'pkgname.dmg'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    exc = pkgsinfo.PackageDoesNotExistError('foo error')
    mock_mpl.Parse().AndRaise(exc)
    self.response.set_status(httplib.BAD_REQUEST).AndReturn(None)
    self.response.out.write('foo error').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutOnNonexistentPackageInfo(self):
    """Test put() with valid input params, but non-existent pkginfo."""
    filename = 'pkgname.dmg'
    body = '<fakexml>blabla</fakexml>'
    pkgloc = '/package/location.pkg'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(None)

    self.response.set_status(httplib.FORBIDDEN).AndReturn(None)
    self.response.out.write('Only updates supported')

    self.mox.ReplayAll()
    self.c.put(filename)
    self.mox.VerifyAll()

  def testPutSuccess(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)

    pkginfo.IsSafeToModify().AndReturn(True)
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()

    self.mox.StubOutWithMock(pkgsinfo.models.Catalog, 'Generate')
    for catalog in catalogs:
      pkgsinfo.models.Catalog.Generate(catalog, delay=1).AndReturn(None)

    mock_mpl.GetXml().AndReturn(body)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, mock_mpl)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.assertEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutSuccessWhenManifestsIsIntentionalEmptyList(self):
    """Test put() with a manifest value that sets the manifest list to []."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = []  # this pkg is in no manifests
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn('')  # == NO manifests
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)

    pkginfo.IsSafeToModify().AndReturn(True)
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()

    self.mox.StubOutWithMock(pkgsinfo.models.Catalog, 'Generate')
    for catalog in catalogs:
      pkgsinfo.models.Catalog.Generate(catalog, delay=1).AndReturn(None)

    mock_mpl.GetXml().AndReturn(body)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, mock_mpl)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.assertEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutSuccessWhenNoManifestsValueSpecified(self):
    """Test put() with no manifest value specified, resulting in no change."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = None
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn(None)
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None) # == no value provided
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)

    pkginfo.IsSafeToModify().AndReturn(True)
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()

    self.mox.StubOutWithMock(pkgsinfo.models.Catalog, 'Generate')
    for catalog in catalogs:
      pkgsinfo.models.Catalog.Generate(catalog, delay=1).AndReturn(None)

    mock_mpl.GetXml().AndReturn(body)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=pkginfo.manifests,
        install_types=install_types, plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, mock_mpl)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    # since the tested function did not set a pkginfo.manifests value
    # then this value is still MockMethod since pkginfo is a mock.
    self.assertNotEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutSuccessWhenHash(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    name = 'foo pkg name'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']
    user = 'foouser'

    self.request.get('hash').AndReturn('goodhash')
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.IsSafeToModify().AndReturn(True)
    self.mox.StubOutWithMock(self.c, '_Hash')
    self.c._Hash(pkginfo.plist).AndReturn('goodhash')
    pkginfo.name = mock_mpl.GetPackageName().AndReturn(name)
    pkginfo.put()

    self.mox.StubOutWithMock(pkgsinfo.models.Catalog, 'Generate')
    for catalog in catalogs:
      pkgsinfo.models.Catalog.Generate(catalog, delay=1).AndReturn(None)

    mock_mpl.GetXml().AndReturn(body)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='pkginfo', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=body)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.assertEqual(pkginfo.plist, mock_mpl)
    self.assertEqual(pkginfo.name, name)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.assertEqual(pkginfo.manifests, manifests)
    self.assertEqual(pkginfo.install_types, install_types)
    self.mox.VerifyAll()

  def testPutWhenHashFail(self):
    """Test put() with valid input params, giving success."""
    filename = 'pkg name.dmg'
    filename_quoted = 'pkg%20name.dmg'
    body = '<fakexml>blabla</fakexml>'
    self.request.body = body
    catalogs = ['catalog1', 'catalog2']
    manifests = ['manifest1', 'manifest2']
    install_types = ['type1', 'type2']

    self.request.get('hash').AndReturn('goodhash')
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.IsSafeToModify().AndReturn(True)
    self.mox.StubOutWithMock(self.c, '_Hash')
    pkginfo.plist = 'foo'
    self.c._Hash(pkginfo.plist).AndReturn('otherhash')
    self.response.set_status(httplib.CONFLICT).AndReturn(None)
    self.response.out.write('Update hash does not match').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.mox.VerifyAll()

  def testPutWhenNotModifiableAndPkginfoChanged(self):
    """Test put() when pkginfo is not modifiable and pkginfo changed."""
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
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'foo'

    pkginfo.IsSafeToModify().AndReturn(False)
    mock_mpl.EqualIgnoringManifestsAndCatalogs(pkginfo.plist).AndReturn(
        False)
    self.response.set_status(httplib.FORBIDDEN).AndReturn(None)
    self.response.out.write('Changes to pkginfo not allowed').AndReturn(
        None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.mox.VerifyAll()

  def testPutWhenNotModifiableButOnlyManifestsChanged(self):
    """Test put() when pkginfo is not modifiable but only manifests changed."""
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
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.request.get('install_types').AndReturn(','.join(install_types))
    mock_mpl = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=pkgsinfo.gaeserver.LEVEL_UPLOADPKG)
    self.mox.StubOutWithMock(pkgsinfo, 'MunkiPackageInfoPlistStrict')
    pkgsinfo.MunkiPackageInfoPlistStrict(body).AndReturn(mock_mpl)
    mock_mpl.Parse().AndReturn(None)
    pkginfo = self.MockModelStatic('PackageInfo', 'get_by_key_name', filename)
    pkginfo.plist = 'foo'

    pkginfo.IsSafeToModify().AndReturn(False)
    mock_mpl.EqualIgnoringManifestsAndCatalogs(pkginfo.plist).AndReturn(
        True)

    # we've previously tested past hash check, so bail there.
    self.mox.StubOutWithMock(self.c, '_Hash')
    self.c._Hash(pkginfo.plist).AndReturn('otherhash')
    self.response.set_status(httplib.CONFLICT).AndReturn(None)
    self.response.out.write('Update hash does not match').AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(filename_quoted)
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
