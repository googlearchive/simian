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
"""uploadpkg module tests."""

import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import uploadpkg


class UploadPackageTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return uploadpkg.UploadPackage()

  def GetTestClassModule(self):
    return uploadpkg

  def testGetSuccess(self):
    """Test get() with success."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsHttps')
    uploadpkg.handlers.IsHttps(self.c).AndReturn(True)
    self.MockDoMunkiAuth()
    self.request.get('mode').AndReturn('success')
    self.request.get('msg', None).AndReturn(None)
    self.request.get('key').AndReturn('key')
    self.response.out.write('key').AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetError(self):
    """Test get() with error mode parameter."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsHttps')
    uploadpkg.handlers.IsHttps(self.c).AndReturn(True)
    self.MockDoMunkiAuth()
    self.request.get('mode').AndReturn('error')
    self.request.get('msg', None).AndReturn('msg')
    self.response.set_status(400)
    self.response.out.write('msg')

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetReturnUploadUrl(self):
    """Test get() with no params, returns upload url."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsHttps')
    uploadpkg.handlers.IsHttps(self.c).AndReturn(True)
    self.MockDoMunkiAuth()
    self.request.get('mode').AndReturn('')
    self.request.get('msg', None).AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'create_upload_url')
    uploadpkg.blobstore.create_upload_url(
        '/uploadpkg', gs_bucket_name=None).AndReturn('/url')
    self.response.out.write('/url').AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testPostNoFileUploaded(self):
    """Test post with no file supplied."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    upload_files = []
    filename = 'fooname.dmg'
    pkginfo = 'anything'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(upload_files)
    self.request.get('pkginfo').AndReturn(None)

    self.MockRedirect('/uploadpkg?mode=error&msg=No%20file%20received')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostNoPackageInfoFileUploaded(self):
    """Test post with no file supplied."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    upload_files = ['some file']
    pkginfo_files = []
    filename = 'fooname.dmg'
    pkginfo = 'anything'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    self.request.get('pkginfo').AndReturn(None)

    self.MockRedirect('/uploadpkg?mode=error&msg=No%20file%20received')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithInvalidPkginfoPlist(self):
    """Tests uploading a package with an invalid pkginfo plist."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    mock_blob1 = self.mox.CreateMockAnything()
    mock_blob2 = self.mox.CreateMockAnything()
    blob1_key = 'blobkey'
    blob2_key = 'pkginfokey'
    upload_files = [mock_blob1]
    pkginfo_files = [mock_blob2]
    filename = 'good.dmg'
    pkginfo = 'BADBADBAD'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    mock_blob2.key().AndReturn(blob2_key)
    pkginfo_str = 'pkginfo'

    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    uploadpkg.gae_util.GetBlobAndDel(blob2_key).AndReturn(pkginfo_str)

    mock_blob1.key().AndReturn(blob1_key)

    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    mock_plist = self.mox.CreateMockAnything()
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)
    mock_plist.Parse().AndRaise(uploadpkg.plist_lib.PlistError)
    self.mox.StubOutWithMock(uploadpkg.logging, 'exception')
    uploadpkg.logging.exception(
        'Invalid pkginfo plist uploaded:\n%s\n', pkginfo_str).AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeBlobDel')
    uploadpkg.gae_util.SafeBlobDel(blob1_key).AndReturn(None)
    self.MockRedirect(
        '/uploadpkg?mode=error&msg=No%20valid%20pkginfo%20received')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithUpdatedPackageBlob(self):
    """Test updating a package (delete old blob)."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    mock_user = self.mox.CreateMockAnything()
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    user = 'foouser'
    name = 'fooname'
    filename = 'name.dmg'
    pkginfo_str = 'pkginfo'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    manifests = ['unstable']
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    self.request.get('user').AndReturn(user)
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    blob2.key().AndReturn('pkginfoblobkey')
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)


    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    mock_plist = self.mox.CreateMockAnything()
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)

    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ObtainLock')
    uploadpkg.gae_util.ObtainLock(
        'pkgsinfo_%s' % filename, timeout=5.0).AndReturn(True)

    pkg = self.MockModelStatic('PackageInfo', 'get_or_insert', filename)
    pkg.IsSafeToModify().AndReturn(True)
    pkg.blobstore_key = 'old_key'
    mock_plist.GetPackageName().AndReturn(name)
    pkg.put().AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeBlobDel')
    uploadpkg.gae_util.SafeBlobDel('old_key').AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.models.Catalog, 'Generate')
    uploadpkg.models.Catalog.Generate(catalogs[0], delay=1)


    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ReleaseLock')
    uploadpkg.gae_util.ReleaseLock('pkgsinfo_%s' % filename).AndReturn(True)

    mock_plist.GetXml().AndReturn(pkginfo_str)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='uploadpkg', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=pkginfo_str)
    mock_log.put().AndReturn(None)

    self.MockRedirect('/uploadpkg?mode=success&key=%s' % blobstore_key)

    self.mox.ReplayAll()
    self.c.post()
    self.assertEqual(blobstore_key, pkg.blobstore_key)
    self.assertEqual(name, pkg.name)
    self.assertEqual(filename, pkg.filename)
    self.assertEqual(install_types, pkg.install_types)
    self.assertEqual(catalogs, pkg.catalogs)
    self.assertEqual(user, pkg.user)
    self.assertEqual(mock_plist, pkg.plist)
    self.mox.VerifyAll()

  def testPostWithNewPackage(self):
    """Test uploading an entirely new package."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    user = 'foouser'
    name = 'fooname'
    filename = 'filename.dmg'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    manifests = ['unstable']
    pkginfo_str = 'pkginfo'
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    self.request.get('user').AndReturn(user)
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(','.join(manifests))
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    blob2.key().AndReturn('pkginfoblobkey')
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)

    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    mock_plist = self.mox.CreateMockAnything()
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)

    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ObtainLock')
    uploadpkg.gae_util.ObtainLock(
        'pkgsinfo_%s' % filename, timeout=5.0).AndReturn(True)

    pkg = self.MockModelStatic('PackageInfo', 'get_or_insert', filename)
    pkg.IsSafeToModify().AndReturn(True)
    pkg.blobstore_key = None
    mock_plist.GetPackageName().AndReturn(name)
    pkg.put().AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.models.Catalog, 'Generate')
    uploadpkg.models.Catalog.Generate(catalogs[0], delay=1)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ReleaseLock')
    uploadpkg.gae_util.ReleaseLock('pkgsinfo_%s' % filename).AndReturn(True)

    mock_plist.GetXml().AndReturn(pkginfo_str)
    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='uploadpkg', filename=filename,
        catalogs=catalogs, manifests=manifests, install_types=install_types,
        plist=pkginfo_str)
    mock_log.put().AndReturn(None)

    self.MockRedirect('/uploadpkg?mode=success&key=%s' % blobstore_key)

    self.mox.ReplayAll()
    self.c.post()
    self.assertEqual(blobstore_key, pkg.blobstore_key)
    self.assertEqual(name, pkg.name)
    self.assertEqual(filename, pkg.filename)
    self.assertEqual(install_types, pkg.install_types)
    self.assertEqual(catalogs, pkg.catalogs)
    self.assertEqual(user, pkg.user)
    self.assertEqual(mock_plist, pkg.plist)
    self.mox.VerifyAll()

  def testPostWithLock(self):
    """Test uploading where pkgsinfo is locked, revert package blob save."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    name = 'fooname'
    filename = 'filename.dmg'
    pkginfo_str = '<plist></plist>'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    blob2.key().AndReturn('pkginfoblobkey')
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)
    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ObtainLock')
    uploadpkg.gae_util.ObtainLock(
        'pkgsinfo_%s' % filename, timeout=5.0).AndReturn(False)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeBlobDel')
    uploadpkg.gae_util.SafeBlobDel(blobstore_key)
    self.MockRedirect('/uploadpkg?mode=error&msg=Could%20not%20lock%20pkgsinfo')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithFailureBecausePkginfoNotModifiable(self):
    """Test uploading where pkginfo is not modifiable."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    name = 'fooname'
    filename = 'filename.dmg'
    pkginfo_str = '<plist></plist>'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    blob2.key().AndReturn('pkginfoblobkey')
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)
    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ObtainLock')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ReleaseLock')
    uploadpkg.gae_util.ObtainLock(
        'pkgsinfo_%s' % filename, timeout=5.0).AndReturn(True)

    pkg = self.MockModelStatic('PackageInfo', 'get_or_insert', filename)
    pkg.IsSafeToModify().AndReturn(False)
    uploadpkg.gae_util.ReleaseLock('pkgsinfo_%s' % filename).AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeBlobDel')
    uploadpkg.gae_util.SafeBlobDel(blobstore_key).AndReturn(None)
    self.MockRedirect(
        '/uploadpkg?mode=error&msg=Package%20is%20not%20modifiable')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithFailure(self):
    """Test uploading where db.put fails, revert package blob save."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    name = 'fooname'
    filename = 'filename.dmg'
    pkginfo_str = '<plist></plist>'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    blob2.key().AndReturn('pkginfoblobkey')
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)
    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(True)

    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ObtainLock')
    uploadpkg.gae_util.ObtainLock(
        'pkgsinfo_%s' % filename, timeout=5.0).AndReturn(True)

    pkg = self.MockModelStatic('PackageInfo', 'get_or_insert', filename)
    pkg.IsSafeToModify().AndReturn(True)
    pkg.blobstore_key = None
    pkg.name = name
    pkg.filename = filename
    mock_plist.GetPackageName().AndReturn(name)
    pkg.put().AndRaise(uploadpkg.db.Error)

    self.mox.StubOutWithMock(uploadpkg.logging, 'exception')
    uploadpkg.logging.exception('error on PackageInfo.put()').AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeBlobDel')
    uploadpkg.gae_util.SafeBlobDel(blobstore_key).AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'SafeEntityDel')
    uploadpkg.gae_util.SafeEntityDel(pkg)
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'ReleaseLock')
    uploadpkg.gae_util.ReleaseLock('pkgsinfo_%s' % filename).AndReturn(True)
    self.MockRedirect('/uploadpkg?mode=error')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithBlobstoreWriteFailure(self):
    """Test uploading where Blobstore POSTs back, but Blob doesn't exist."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.MockSelf('get_uploads')
    self.mox.StubOutWithMock(uploadpkg.gae_util, 'GetBlobAndDel')
    self.mox.StubOutWithMock(uploadpkg.plist_lib, 'MunkiPackageInfoPlist')
    self.mox.StubOutWithMock(uploadpkg.blobstore, 'BlobInfo')
    mock_plist = self.mox.CreateMockAnything()
    blob = self.mox.CreateMockAnything()
    blob2 = self.mox.CreateMockAnything()
    upload_files = [blob]
    pkginfo_files = [blob2]
    name = 'fooname'
    filename = 'filename.dmg'
    pkginfo_str = '<plist></plist>'
    install_types = ['managed_installs', 'managed_updates']
    catalogs = ['unstable']
    pkginfo_dict = {
        'installer_item_location': filename,
        'installer_item_hash': 'hash'}
    blobstore_key = 'fookey'

    blob2.key().AndReturn('pkginfoblobkey')
    self.request.get('user').AndReturn('foouser')
    self.request.get('name').AndReturn(filename)
    self.request.get('install_types').AndReturn(','.join(install_types))
    self.request.get('catalogs', None).AndReturn(','.join(catalogs))
    self.request.get('manifests', None).AndReturn(None)
    self.c.get_uploads('file').AndReturn(upload_files)
    self.c.get_uploads('pkginfo').AndReturn(pkginfo_files)
    uploadpkg.gae_util.GetBlobAndDel('pkginfoblobkey').AndReturn(pkginfo_str)
    uploadpkg.plist_lib.MunkiPackageInfoPlist(pkginfo_str).AndReturn(
        mock_plist)
    mock_plist.Parse().AndReturn(None)
    blob.key().AndReturn(blobstore_key)
    mock_plist.__getitem__('installer_item_location').AndReturn(filename)
    mock_plist.__getitem__('installer_item_hash').AndReturn('hash')
    uploadpkg.blobstore.BlobInfo.get(blobstore_key).AndReturn(None)
    self.mox.StubOutWithMock(uploadpkg.logging, 'critical')
    uploadpkg.logging.critical(
        'Blobstore returned a key for %s that does not exist: %s',
        filename, blobstore_key).AndReturn(None)
    self.MockRedirect('/uploadpkg?mode=error&msg=Blobstore%20failure')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWithMissingArgs(self):
    """Test updating a package with missing name/track/etc."""
    self.mox.StubOutWithMock(uploadpkg.handlers, 'IsBlobstore')
    msg = 'uploadpkg POST required parameters missing'

    # missing user
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.request.get('user').AndReturn('')
    self.request.get('name').AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn(None)
    self.MockRedirect('/uploadpkg?mode=error&msg=%s' % msg)
    # missing name
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.request.get('user').AndReturn('anything')
    self.request.get('name').AndReturn('')
    self.request.get('install_types').AndReturn('anything')
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn(None)
    self.MockRedirect('/uploadpkg?mode=error&msg=%s' % msg)
    # missing install_types
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.request.get('user').AndReturn('anything')
    self.request.get('name').AndReturn('anything')
    self.request.get('install_types').AndReturn('')
    self.request.get('catalogs', None).AndReturn('anything')
    self.request.get('manifests', None).AndReturn(None)
    self.MockRedirect('/uploadpkg?mode=error&msg=%s' % msg)
    # missing catalogs
    uploadpkg.handlers.IsBlobstore().AndReturn(True)
    self.MockDoMunkiAuth(require_level=uploadpkg.gaeserver.LEVEL_UPLOADPKG)
    self.request.get('user').AndReturn('anything')
    self.request.get('name').AndReturn('anything')
    self.request.get('install_types').AndReturn('anything')
    self.request.get('catalogs', None).AndReturn(None)
    self.request.get('manifests', None).AndReturn(None)
    self.MockRedirect('/uploadpkg?mode=error&msg=%s' % msg)

    self.mox.ReplayAll()
    self.c.post()
    self.c.post()
    self.c.post()
    self.c.post()
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
