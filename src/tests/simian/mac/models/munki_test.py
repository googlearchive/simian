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
"""Munki models module tests."""

import datetime

import tests.appenginesdk
import mock
import stubout
import mox
import stubout

from google.appengine.ext import testbed

from simian.mac.common import datastore_locks
from google.apputils import app
from google.apputils import basetest
from tests.simian.mac.common import test
from simian.mac.models import munki as models


class CatalogTest(mox.MoxTestBase, test.AppengineTest):
  """Test Catalog class."""

  def setUp(self):
    test.AppengineTest.setUp(self)
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    test.AppengineTest.tearDown(self)
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGenerateAsync(self):
    """Tests calling Generate(delay=2)."""
    name = 'catalogname'
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(models.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-catalog-%s-%s' % (
        name, '2010-09-02-19-30-21-377827')
    models.datetime.datetime.utcnow().AndReturn(utcnow)
    models.deferred.defer(
        models.Catalog.Generate, name, _name=deferred_name, _countdown=2)
    self.mox.ReplayAll()
    models.Catalog.Generate(name, delay=2)
    self.mox.VerifyAll()

  def testGenerateSuccess(self):
    """Tests the success path for Generate()."""
    name = 'goodname'
    plist1 = '<dict><key>foo</key><string>bar</string></dict>'
    mock_plist1 = self.mox.CreateMockAnything()
    pkg1 = test.GenericContainer(
        plist=mock_plist1, name='foo', mtime=datetime.datetime.utcnow())
    plist2 = '<dict><key>foo</key><string>bar</string></dict>'
    mock_plist2 = self.mox.CreateMockAnything()
    pkg2 = test.GenericContainer(
        plist=mock_plist2, name='bar', mtime=datetime.datetime.utcnow())

    self.mox.StubOutWithMock(models.Manifest, 'Generate')
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    self.mox.StubOutWithMock(models.Catalog, 'get_or_insert')
    self.mox.StubOutWithMock(models.Catalog, 'DeleteMemcacheWrap')

    mock_model = self.mox.CreateMockAnything()
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('catalogs =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([pkg1, pkg2])
    pkg1.plist.GetXmlContent(indent_num=1).AndReturn(plist1)
    pkg2.plist.GetXmlContent(indent_num=1).AndReturn(plist2)

    mock_catalog = self.mox.CreateMockAnything()
    models.Catalog.get_or_insert(name).AndReturn(mock_catalog)
    mock_catalog.put(avoid_mtime_update=True).AndReturn(None)

    models.Catalog.DeleteMemcacheWrap(name).AndReturn(None)
    models.Manifest.Generate(name, delay=1).AndReturn(None)

    m = mock.Mock()
    with mock.patch.object(
        datastore_locks, 'DatastoreLock', return_value=m) as lock_mock:
      self.mox.ReplayAll()
      models.Catalog.Generate(name)
      self.mox.VerifyAll()

      lock_mock.assert_called_once_with('catalog_lock_goodname')

    m.assert_has_calls([
        mock.call.Acquire(timeout=600, max_acquire_attempts=2),
        mock.call.Release()])

    self.assertEqual(mock_catalog.name, name)
    xml = '\n'.join([plist1, plist2])
    expected_plist = models.constants.CATALOG_PLIST_XML % xml
    self.assertEqual(expected_plist, mock_catalog.plist)
    self.assertEqual(mock_catalog.package_names, ['foo', 'bar'])

  def testGenerateWithNoPkgsinfo(self):
    """Tests Catalog.Generate() where no coorresponding PackageInfo exist."""
    name = 'emptyname'
    self.mox.StubOutWithMock(models.Manifest, 'Generate')
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    self.mox.StubOutWithMock(models.Catalog, 'get_or_insert')
    self.mox.StubOutWithMock(models.Catalog, 'DeleteMemcacheWrap')

    mock_model = self.mox.CreateMockAnything()
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('catalogs =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([])

    mock_catalog = self.mox.CreateMockAnything()
    models.Catalog.get_or_insert(name).AndReturn(mock_catalog)
    mock_catalog.put(avoid_mtime_update=True).AndReturn(None)

    models.Catalog.DeleteMemcacheWrap(name).AndReturn(None)
    models.Manifest.Generate(name, delay=1).AndReturn(None)

    self.mox.ReplayAll()
    models.Catalog.Generate(name)
    self.assertEqual(mock_catalog.name, name)
    expected_plist = models.constants.CATALOG_PLIST_XML % '\n'.join([])
    self.assertEqual(expected_plist, mock_catalog.plist)
    self.assertEqual(mock_catalog.package_names, [])
    self.mox.VerifyAll()

  def testGenerateWithPlistParseError(self):
    """Tests Generate() where plist.GetXmlDocument() raises plist.Error."""
    name = 'goodname'
    mock_plist1 = self.mox.CreateMockAnything()
    pkg1 = test.GenericContainer(plist=mock_plist1, name='foo')
    mock_model = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('catalogs =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([pkg1])
    mock_plist1.GetXmlContent(indent_num=1).AndRaise(models.plist_lib.Error)

    self.mox.ReplayAll()
    self.assertRaises(
        models.plist_lib.Error, models.Catalog.Generate, name)
    self.mox.VerifyAll()

  def testGenerateWithDbError(self):
    """Tests Generate() where put() raises db.Error."""
    name = 'goodname'
    plist1 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    mock_plist1 = self.mox.CreateMockAnything()
    pkg1 = test.GenericContainer(
        plist=mock_plist1, name='foo', mtime=datetime.datetime.utcnow())
    plist2 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    mock_plist2 = self.mox.CreateMockAnything()
    pkg2 = test.GenericContainer(
        plist=mock_plist2, name='bar', mtime=datetime.datetime.utcnow())

    mock_model = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('catalogs =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([pkg1, pkg2])
    mock_plist1.GetXmlContent(indent_num=1).AndReturn(plist1)
    mock_plist2.GetXmlContent(indent_num=1).AndReturn(plist2)

    mock_catalog = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.Catalog, 'get_or_insert')
    models.Catalog.get_or_insert(name).AndReturn(mock_catalog)
    mock_catalog.put(avoid_mtime_update=True).AndRaise(models.db.Error)

    self.mox.ReplayAll()
    self.assertRaises(
        models.db.Error, models.Catalog.Generate, name)
    self.mox.VerifyAll()

  def testGenerateLocked(self):
    """Tests Generate() where name is locked."""
    name = 'lockedname'
    datastore_locks.DatastoreLock('catalog_lock_%s' % name).Acquire()

    # here is where Generate calls itself; can't stub the method we're
    # testing, so mock the calls that happen as a result.
    self.stubs.Set(models.deferred, 'defer', self.mox.CreateMockAnything())
    models.deferred.defer(
        models.Catalog.Generate, name, _name=mox.IgnoreArg(), _countdown=10)

    self.mox.ReplayAll()
    models.Catalog.Generate(name)
    self.mox.VerifyAll()


class ManifestTest(mox.MoxTestBase, test.AppengineTest):
  """Test Manifest class."""

  def setUp(self):
    test.AppengineTest.setUp(self)
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    test.AppengineTest.tearDown(self)
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGenerateAsync(self):
    """Tests calling Manifest.Generate(delay=2)."""
    name = 'manifestname'
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(models.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-manifest-%s-%s' % (
        name, '2010-09-02-19-30-21-377827')
    models.datetime.datetime.utcnow().AndReturn(utcnow)
    models.deferred.defer(
        models.Manifest.Generate, name, _name=deferred_name, _countdown=2)
    self.mox.ReplayAll()
    models.Manifest.Generate(name, delay=2)
    self.mox.VerifyAll()

  def testGenerateSuccess(self):
    """Tests the success path for Manifest.Generate()."""
    name = 'goodname'
    pkg1 = test.GenericContainer(install_types=['footype1'], name='pkg1')
    pkg2 = test.GenericContainer(
        install_types=['footype1', 'footype2'], name='pkg2')
    manifest_dict = {
        'catalogs': [name, 'apple_update_metadata'],
        pkg1.install_types[0]: [pkg1.name, pkg2.name],
        pkg2.install_types[1]: [pkg2.name],
    }
    self.stubs.Set(
        models.plist_lib,
        'MunkiManifestPlist',
        self.mox.CreateMock(models.plist_lib.MunkiManifestPlist))

    mock_model = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('manifests =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([pkg1, pkg2])

    mock_manifest = self.mox.CreateMockAnything()
    mock_manifest.plist = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(models.Manifest, 'get_or_insert')
    models.Manifest.get_or_insert(name).AndReturn(mock_manifest)
    mock_manifest.plist.SetContents(manifest_dict)
    mock_manifest.put().AndReturn(None)
    self.mox.StubOutWithMock(models.Manifest, 'DeleteMemcacheWrap')
    models.Manifest.DeleteMemcacheWrap(name).AndReturn(None)

    m = mock.Mock()
    with mock.patch.object(
        datastore_locks, 'DatastoreLock', return_value=m) as lock_mock:
      self.mox.ReplayAll()
      models.Manifest.Generate(name)
      self.mox.VerifyAll()

      lock_mock.assert_called_once_with('manifest_lock_goodname')

    m.assert_has_calls([
        mock.call.Acquire(timeout=30, max_acquire_attempts=1),
        mock.call.Release()])

  def testGenerateDbError(self):
    """Tests Manifest.Generate() with db Error."""
    name = 'goodname'

    mock_model = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('manifests =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndRaise(models.db.Error)

    self.mox.ReplayAll()
    self.assertRaises(models.db.Error, models.Manifest.Generate, name)
    self.mox.VerifyAll()

  def testGenerateWithNoPkgsinfo(self):
    """Tests Manifest.Generate() where no coorresponding PackageInfo exist."""
    name = 'emptyname'
    manifest_dict = {
        'catalogs': [name, 'apple_update_metadata'],
    }
    self.stubs.Set(
        models.plist_lib,
        'MunkiManifestPlist',
        self.mox.CreateMock(models.plist_lib.MunkiManifestPlist))

    mock_model = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(models.PackageInfo, 'all')
    models.PackageInfo.all().AndReturn(mock_model)
    mock_model.filter('manifests =', name).AndReturn(mock_model)
    mock_model.fetch(None).AndReturn([])

    mock_manifest = self.mox.CreateMockAnything()
    mock_manifest.plist = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(models.Manifest, 'get_or_insert')
    models.Manifest.get_or_insert(name).AndReturn(mock_manifest)
    mock_manifest.plist.SetContents(manifest_dict)
    mock_manifest.put().AndReturn(None)
    self.mox.StubOutWithMock(models.Manifest, 'DeleteMemcacheWrap')
    models.Manifest.DeleteMemcacheWrap(name).AndReturn(None)

    self.mox.ReplayAll()
    models.Manifest.Generate(name)
    self.mox.VerifyAll()

  def testGenerateLocked(self):
    """Tests Manifest.Generate() where name is locked."""
    name = 'lockedname'
    datastore_locks.DatastoreLock('manifest_lock_%s' % name).Acquire()

    # here is where Manifest.Generate calls itself; can't stub the method we're
    # testing, so mock the calls that happen as a result.
    self.stubs.Set(models.deferred, 'defer', self.mox.CreateMockAnything())
    models.deferred.defer(
        models.Manifest.Generate, name, _name=mox.IgnoreArg(), _countdown=5)

    self.mox.ReplayAll()
    models.Manifest.Generate(name)
    self.mox.VerifyAll()


class PackageInfoTest(mox.MoxTestBase):
  """Test PackageInfo class."""

  def setUp(self):
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='foo@example.com',
        USER_ID='1337',
        USER_IS_ADMIN='0')
    self.testbed.init_all_stubs()

    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.testbed.deactivate()

    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GetTestPackageInfoPlist(self, d=None):
    """String concatenates a description and returns test plist xml."""
    if not d:
      d = {}
    for k in ['desc', 'name', 'installer_item_hash', 'version']:
      if k not in d:
        d[k] = 'foo%s' % k

    # Build xml array of catalogs.
    if 'catalogs' not in d:
      d['catalogs'] = ['unstable']
    catalogs = []
    for catalog in d['catalogs']:
      catalogs.append('<string>%s</string>' % catalog)
    d['catalogs'] = ''.join(catalogs)

    return (
        '<plist><dict><key>name</key><string>%(name)s</string>'
        '<key>version</key><string>%(version)s</string>'
        '<key>installer_item_hash</key><string>%(installer_item_hash)s</string>'
        '<key>installer_item_location</key><string>filename.dmg</string>'
        '<key>catalogs</key><array>%(catalogs)s</array>'
        '<key>description</key><string>%(desc)s</string></dict></plist>' % d)

  def testGetDescription(self):
    """Tests getting PackageInfo.description property."""
    p = models.PackageInfo()
    desc = 'basic'
    p.plist = self._GetTestPackageInfoPlist({'desc': desc})

    self.mox.ReplayAll()
    self.assertEqual(desc, p._GetDescription())
    self.mox.VerifyAll()

  def testGetDescriptionEmptyStr(self):
    """Tests getting PackageInfo.description property, when desc is empty."""
    p = models.PackageInfo()
    desc = ''
    p.plist = self._GetTestPackageInfoPlist({'desc': desc})

    self.mox.ReplayAll()
    self.assertEqual('', p._GetDescription())
    self.mox.VerifyAll()

  def testGetDescriptionWithAvgDurationText(self):
    """Tests PackageInfo.description property with avg duration text."""
    p = models.PackageInfo()
    basic_desc = 'basic'
    avg_duration_text = models.PackageInfo.AVG_DURATION_TEXT % (25000, 41)
    full_desc = '%s\n\n%s' % (basic_desc, avg_duration_text)
    p.plist = self._GetTestPackageInfoPlist({'desc': full_desc})

    self.mox.ReplayAll()
    self.assertEqual(basic_desc, p._GetDescription())
    self.mox.VerifyAll()

  def testSetDescription(self):
    """Set PackageInfo.description property, sans avg duration text."""
    p = models.PackageInfo()
    desc = 'basic'
    p.plist = self._GetTestPackageInfoPlist({'desc': desc})

    self.mox.ReplayAll()
    p._SetDescription(desc)
    self.assertEqual(desc, p.description)
    self.mox.VerifyAll()

  def testSetDescriptionPreservingExistingAvgDurationText(self):
    """Set PackageInfo.description property, preserving avg duration text."""
    p = models.PackageInfo()
    basic_desc = 'basic'
    avg_duration_text = models.PackageInfo.AVG_DURATION_TEXT % (25000, 41)
    full_desc = 'ANYTHING_HERE\n\n%s' % avg_duration_text
    p.plist = self._GetTestPackageInfoPlist({'desc': full_desc})
    expected_new_desc = full_desc.replace('ANYTHING_HERE', basic_desc)

    self.mox.ReplayAll()
    p._SetDescription(basic_desc)
    self.assertEqual(basic_desc, p.description)
    self.assertEqual(expected_new_desc, p.plist['description'])
    self.mox.VerifyAll()

  def testSetDescriptionWithUpdatedAvgDurationText(self):
    """Set PackageInfo.description property, preserving avg duration text."""
    p = models.PackageInfo()
    avg_duration_text = models.PackageInfo.AVG_DURATION_TEXT % (25000, 41)
    old_full_desc = 'NOT_BASIC\n\n%s' % avg_duration_text
    p.plist = self._GetTestPackageInfoPlist({'desc': old_full_desc})

    basic_desc = 'basic'
    avg_duration_text = models.PackageInfo.AVG_DURATION_TEXT % (25555, 45)
    new_full_desc = '%s\n\n%s' % (basic_desc, avg_duration_text)

    self.mox.ReplayAll()
    p._SetDescription(new_full_desc)
    self.assertEqual(basic_desc, p.description)
    self.assertEqual(new_full_desc, p.plist['description'])
    self.mox.VerifyAll()

  def testUpdateWithObtainLockFailure(self):
    """Test Update() with a failure obtaining the lock."""
    p = models.PackageInfo()
    p.filename = 'foofile.dmg'
    datastore_locks.DatastoreLock('pkgsinfo_%s' % p.filename).Acquire()

    self.mox.ReplayAll()
    self.assertRaises(models.PackageInfoLockError, p.Update)
    self.mox.VerifyAll()

  def testMakeSafeToModifyWithoutProposals(self):
    """Test MakeSafeToModify() with out proposals and package in catalogs."""
    p = models.PackageInfo()
    p.catalogs = ['unstable', 'testing', 'stable']
    p.manifests = ['unstable', 'testing', 'stable']

    self.mox.StubOutWithMock(models.PackageInfo, 'approval_required')
    models.PackageInfo.approval_required = False
    self.mox.StubOutWithMock(models.PackageInfo, 'Update')
    models.PackageInfo.Update(catalogs=[], manifests=[])

    self.mox.ReplayAll()
    p.MakeSafeToModify()
    self.mox.VerifyAll()

  def _UpdateTestHelper(
      self, filename, pkginfo, plist_xml=None, create_new=False,
      safe_to_modify=True, unsafe_properties_changed=False,
      filename_exists=False, **kwargs):
    """Test helper for Update()."""
    catalogs = kwargs.get('catalogs')
    manifests = kwargs.get('manifests')
    install_types = kwargs.get('install_types')
    manifest_mod_access = kwargs.get('manifest_mod_access')
    name = kwargs.get('name')
    display_name = kwargs.get('display_name')
    unattended_install = kwargs.get('unattended_install')
    unattended_uninstall = kwargs.get('unattended_uninstall')
    description = kwargs.get('description')
    version = kwargs.get('version')
    minimum_os_version = kwargs.get('minimum_os_version')
    maximum_os_version = kwargs.get('maximum_os_version')
    force_install_after_date = kwargs.get('force_install_after_date')

    self.mox.StubOutWithMock(models.PackageInfo, 'approval_required')
    models.PackageInfo.approval_required = False

    self.mox.StubOutWithMock(models.PackageInfo, 'get_by_key_name')

    if create_new:
      pkginfo = self.mox.CreateMockAnything()
      pkginfo.catalogs = []
      pkginfo.manifests = []
      pkginfo.install_types = []
      pkginfo.manifest_mod_access = []
      if filename_exists:
        models.PackageInfo.get_by_key_name(filename).AndReturn(True)
        self.mox.ReplayAll()
        models.PackageInfo.UpdateFromPlist(plist_xml, create_new=create_new)
      else:
        models.PackageInfo.get_by_key_name(filename).AndReturn(None)
      self.mox.StubOutWithMock(models.PackageInfo, '_New')
      models.PackageInfo._New(filename).AndReturn(pkginfo)
    elif plist_xml:
      models.PackageInfo.get_by_key_name(filename).AndReturn(pkginfo)

    if create_new:
      original_plist = None
    else:
      original_plist = pkginfo.plist.GetXml()

    pkginfo.filename = filename

    self.mox.StubOutWithMock(pkginfo, 'IsSafeToModify')
    pkginfo.IsSafeToModify().AndReturn(safe_to_modify)
    if not safe_to_modify:
      if plist_xml or unsafe_properties_changed:
        # If not safe to modify and plist_xml was passed, an exception will be
        # raised after releasing the lock.
        self.mox.ReplayAll()
        if plist_xml:
          models.PackageInfo.UpdateFromPlist(plist_xml)
        else:
          pkginfo.Update(**kwargs)
        return

    self.mox.StubOutWithMock(pkginfo, 'VerifyPackageIsEligibleForNewCatalogs')
    pkginfo.VerifyPackageIsEligibleForNewCatalogs(
        mox.IsA(list)).AndReturn(None)

    self.mox.StubOutWithMock(pkginfo, 'put')
    pkginfo.put().AndReturn(None)

    self.mox.StubOutWithMock(models.Catalog, 'Generate')

    if plist_xml:
      pl = models.plist_lib.MunkiPackageInfoPlist(plist_xml)
      pl.Parse()
      if create_new:
        new_catalogs = []
        changed_catalogs = []
      else:
        new_catalogs = pl['catalogs']
        changed_catalogs = pkginfo.catalogs + new_catalogs
    else:
      new_catalogs = catalogs or pkginfo.catalogs
      if catalogs:
        changed_catalogs = set(catalogs + pkginfo.catalogs)
      else:
        changed_catalogs = pkginfo.catalogs

    for catalog in sorted(changed_catalogs, reverse=True):
      models.Catalog.Generate(catalog, delay=1).AndReturn(None)

    self.mox.StubOutWithMock(models.users, 'get_current_user')
    mock_user = self.mox.CreateMockAnything()
    models.users.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn('foouser@example.com')
    self.mox.StubOutWithMock(models.base, 'AdminPackageLog')
    mock_log = self.mox.CreateMockAnything()
    if safe_to_modify:
      models.base.AdminPackageLog(
          user='foouser@example.com', action='pkginfo', filename=filename,
          catalogs=new_catalogs or [], manifests=manifests or [],
          original_plist=original_plist, install_types=install_types or [],
          manifest_mod_access=manifest_mod_access or [],
      ).AndReturn(mock_log)
    else:
      # if not safe to modify, only catalogs/manifests can be changed.
      models.base.AdminPackageLog(
          user='foouser@example.com', action='pkginfo', filename=filename,
          catalogs=new_catalogs or [], manifests=manifests or [],
          original_plist=original_plist, install_types=[],
          manifest_mod_access=[],
      ).AndReturn(mock_log)

    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    if plist_xml:
      models.PackageInfo.UpdateFromPlist(plist_xml, create_new=create_new)
    else:
      pkginfo.Update(
          catalogs=catalogs, manifests=manifests,
          install_types=install_types, manifest_mod_access=manifest_mod_access,
          name=name, display_name=display_name,
          unattended_install=unattended_install, description=description,
          version=version, minimum_os_version=minimum_os_version,
          maximum_os_version=maximum_os_version,
          force_install_after_date=force_install_after_date,
          unattended_uninstall=unattended_uninstall)
    # Verify that the pkginfo.plist property was set.
    self.assertEqual(mock_log.plist, pkginfo.plist)

    return pkginfo

  def testUpdatePromoteToStable(self):
    """Test Update() when promoting a package to stable."""
    p = models.PackageInfo()
    p.plist = self._GetTestPackageInfoPlist({'desc': 'foodesc'})
    p.catalogs = ['unstable', 'testing']
    p.manifests = ['unstable', 'testing']

    catalogs = ['unstable', 'testing', 'stable']
    manifests = ['unstable', 'testing', 'stable']

    m = mock.Mock()
    with mock.patch.object(
        datastore_locks, 'DatastoreLock', return_value=m) as lock_mock:
      pkginfo = self._UpdateTestHelper(
          'fooname.dmg', p, catalogs=catalogs, manifests=manifests)
      self.assertEqual(pkginfo.catalogs, catalogs)
      self.mox.VerifyAll()

      lock_mock.assert_called_once_with('pkgsinfo_fooname.dmg')

    m.assert_has_calls([
        mock.call.Acquire(timeout=600, max_acquire_attempts=5),
        mock.call.Release()])

  def testUpdateDemoteFromStable(self):
    """Test Update() when demoting a package from stable."""
    p = models.PackageInfo()
    p.plist = self._GetTestPackageInfoPlist({'desc': 'foodesc'})
    p.catalogs = ['unstable', 'testing', 'stable']
    p.manifests = ['unstable', 'testing', 'stable']

    catalogs = ['unstable', 'testing']
    manifests = ['unstable', 'testing']
    pkginfo = self._UpdateTestHelper(
        'zooooo.dmg', p, catalogs=catalogs, manifests=manifests)
    self.assertEqual(pkginfo.catalogs, catalogs)
    self.mox.VerifyAll()

  def testUpdateWithMultipleNewProperties(self):
    """Tests Update() with several some new and some updated properties."""
    p = models.PackageInfo()
    p.plist = self._GetTestPackageInfoPlist({'desc': 'foodesc'})
    p.catalogs = ['unstable']
    p.install_types = ['should be changed']
    # pkginfo.manifests purposefully not set.
    # pkginfo.manifest_mod_access purposefully not set.

    install_types = ['managed_updates', 'optional_installs']
    manifests = ['unstable']
    manifest_mod_access = ['support']
    pkginfo = self._UpdateTestHelper(
        'foo.dmg', p, install_types=install_types, manifests=manifests,
        manifest_mod_access=manifest_mod_access)
    self.assertEqual(install_types, pkginfo.install_types)
    self.assertEqual(manifests, pkginfo.manifests)
    self.assertEqual(manifest_mod_access, pkginfo.manifest_mod_access)
    self.mox.VerifyAll()

  def testUpdateWithNewPlistProperties(self):
    """Test Update() when passing params that change plist XML properties."""
    p = models.PackageInfo()
    orig_version = '9.0.0.0.1'
    p.plist = self._GetTestPackageInfoPlist(
        {'desc': 'foodesc', 'version': orig_version})
    p.catalogs = ['unstable']

    description = 'zomg new description!!!'
    install_types = ['managed_updates', 'optional_installs']
    manifests = ['unstable']
    version = '10.0.0.0.1-gg1'
    minimum_os_version = '10.5.8'
    maximum_os_version = ''
    force_install_after_date = datetime.datetime(2012, 2, 23, 13, 0, 0)
    pkginfo = self._UpdateTestHelper(
        'foo.dmg', p, install_types=install_types, manifests=manifests,
        description=description, version=version,
        minimum_os_version=minimum_os_version,
        maximum_os_version=maximum_os_version,
        force_install_after_date=force_install_after_date)
    self.assertEqual(description, pkginfo.plist['description'])
    self.assertEqual(install_types, pkginfo.install_types)
    self.assertEqual(manifests, pkginfo.manifests)
    self.assertEqual(version, pkginfo.plist['version'])
    self.assertEqual(minimum_os_version, pkginfo.plist['minimum_os_version'])
    self.assertTrue('maximum_os_version' not in pkginfo.plist)
    self.assertEqual(
        force_install_after_date, pkginfo.plist['force_install_after_date'])
    self.mox.VerifyAll()

  def testUpdateWithNewPropertiesButIsNotSafeToModifySuccess(self):
    """Test Update() when IsSafeToModify() is False, but only cats changed."""
    p = models.PackageInfo()
    orig_desc = 'orig_desc'
    orig_install_types = ['managed_updates', 'managed_installs']
    p.plist = self._GetTestPackageInfoPlist({'desc': orig_desc})
    p.catalogs = ['unstable', 'testing', 'stable']
    p.manifests = ['unstable', 'testing', 'stable']
    p.plist['unattended_install'] = True
    p.plist['unattended_uninstall'] = True
    p.plist['install_types'] = orig_install_types

    manifests = ['unstable']
    catalogs = ['unstable']

    pkginfo = self._UpdateTestHelper(
        'foo.dmg', p, catalogs=catalogs, manifests=manifests,
        safe_to_modify=False, unsafe_properties_changed=False)
    self.assertEqual(catalogs, pkginfo.catalogs)
    self.assertEqual(manifests, pkginfo.manifests)
    self.assertEqual(orig_desc, pkginfo.description)
    self.assertEqual(True, pkginfo.plist['unattended_install'])
    self.assertEqual(True, pkginfo.plist['unattended_uninstall'])
    self.assertEqual(orig_install_types, pkginfo.plist['install_types'])
    self.mox.VerifyAll()

  def testUpdateWithNewPropertiesButIsNotSafeToModifyFailure(self):
    """Test Update() when IsSafeToModify() is False and Update fails."""
    p = models.PackageInfo()
    orig_desc = 'orig_desc'
    orig_name = 'fooname'
    p.plist = self._GetTestPackageInfoPlist(
        {'desc': orig_desc, 'name': orig_name})
    p.catalogs = ['unstable', 'testing', 'stable']
    p.manifests = ['unstable', 'testing', 'stable']
    p.name = orig_name

    description = 'zomg new description!!!'
    manifests = ['unstable']
    catalogs = ['unstable']

    self.assertRaises(
        models.PackageInfoUpdateError,
        self._UpdateTestHelper, 'foo.dmg', p, catalogs=catalogs,
        manifests=manifests, name='NEWWW', description=description,
        safe_to_modify=False, unsafe_properties_changed=True)
    self.mox.VerifyAll()

  def testUpdateFromPlist(self):
    """Test UpdateFromPlist() with new plist values."""
    p = models.PackageInfo()
    p.plist = self._GetTestPackageInfoPlist({'desc': 'OLD', 'name': 'OLD'})

    new_desc = 'NEW DESC!!!'
    new_name = 'newname'
    new_hash = 'zomgHASH'
    new_catalogs = ['unstable', 'testing', 'stable']
    xml = self._GetTestPackageInfoPlist(
        {'desc': new_desc, 'name': new_name, 'installer_item_hash': new_hash,
         'catalogs': new_catalogs})

    pkginfo = self._UpdateTestHelper('filename.dmg', p, plist_xml=xml)

    self.assertEqual(new_name, pkginfo.name)
    self.assertEqual(new_name, pkginfo.plist['name'])
    self.assertEqual(new_desc, pkginfo.plist['description'])
    self.assertEqual(new_hash, pkginfo.plist['installer_item_hash'])
    self.assertEqual(new_hash, pkginfo.pkgdata_sha256)
    self.assertEqual(new_catalogs, pkginfo.catalogs)
    self.assertEqual(new_catalogs, pkginfo.plist['catalogs'])
    self.mox.VerifyAll()

  def testUpdateFromPlistWithPkginfoNotSafeToModify(self):
    """Test UpdateFromPlist() when pkginfo is not safe to mod."""
    p = models.PackageInfo()
    p.plist = self._GetTestPackageInfoPlist({'desc': 'OLD', 'name': 'OLD'})
    xml = self._GetTestPackageInfoPlist({'desc': 'NEW', 'name': 'NEW'})

    self.assertRaises(
        models.PackageInfoUpdateError,
        self._UpdateTestHelper,
        'filename.dmg', p, plist_xml=xml, safe_to_modify=False)

  def testUpdateFromPlistWithInvalidPlistXml(self):
    """Test UpdateFromPlist() with an invalid."""
    self.assertRaises(
        models.PackageInfoUpdateError,
        models.PackageInfo.UpdateFromPlist, '<plist>NOT VALID PLIST</plist>')

  def testUpdateFromPlistCreateNewTrue(self):
    """Test UpdateFromPlist(create_new=True)."""
    filename = 'filename.dmg'
    name = 'foopkgname'
    catalogs = ['unstable', 'testing']
    pkgdata_sha256 = 'abcd1234'
    xml = self._GetTestPackageInfoPlist(
        {'filename': filename, 'name': name, 'catalogs': catalogs,
         'installer_item_hash': pkgdata_sha256})

    pkginfo = self._UpdateTestHelper(
        filename, None, plist_xml=xml, create_new=True)

    self.assertEqual(name, pkginfo.name)
    self.assertEqual(filename, pkginfo.filename)
    # Test that catalogs were ignored/wiped.
    self.assertEqual([], pkginfo.catalogs)
    self.assertEqual([], pkginfo.plist['catalogs'])
    self.assertEqual(pkgdata_sha256, pkginfo.plist['installer_item_hash'])
    self.assertEqual(pkgdata_sha256, pkginfo.pkgdata_sha256)
    self.mox.VerifyAll()

  def testUpdateFromPlistCreateNewTrueButPreexistingKeyName(self):
    """Test UpdateFromPlist(create_new=True) where the filename is in use."""
    filename = 'filename.dmg'
    name = 'foopkgname'
    xml = self._GetTestPackageInfoPlist(
        {'filename': filename, 'name': name})

    self.assertRaises(
        models.PackageInfoUpdateError,
        self._UpdateTestHelper,
        filename, None, plist_xml=xml, create_new=True, filename_exists=True)
    self.mox.VerifyAll()

  def testBuildProposalBodyUrlEncodesFileName(self):
    p = models.PackageInfo()
    pip = models.PackageInfoProposal._New(p)
    body = pip._BuildProposalBody('foo.com', 'file name.dmg')
    self.assertTrue('https://foo.com/admin/package/file%20name.dmg' in body)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
