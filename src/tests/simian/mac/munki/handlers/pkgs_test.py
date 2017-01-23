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
"""Munki pkgs module tests."""

import datetime
import httplib
import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import pkgs


class PackagesTest(test.RequestHandlerTest):
  """pkgs module test helper class."""

  def MockQueryFilename(self, filename, blobstore_key=None, **kwargs):
    """Helper method to get a PackageInfo by filename."""
    if blobstore_key is None:
      mock_pkg = None
    else:
      mock_pkg = self.mox.CreateMockAnything()
      mock_pkg.blobstore_key = blobstore_key
      for k in kwargs:
        setattr(mock_pkg, k, kwargs[k])

    self.MockModelStaticBase(
        'PackageInfo', 'MemcacheWrappedGet', filename).AndReturn(mock_pkg)


class PackagesHandlerTest(PackagesTest):
  """pkgs.Packages handlers tests."""

  def GetTestClassInstance(self):
    return pkgs.Packages()

  def GetTestClassModule(self):
    return pkgs

  def testGetSuccessHelper(self, pkg_modified_since=True, supply_etag='etag'):
    """Tests Packages.get()."""
    filename = u'good name.dmg'
    filename_quoted = 'good%20name.dmg'
    blobinfo_memcache_key = 'blobinfo_%s' % filename
    blobstore_key = 'fookey'
    mod_since_date = 'foo str date'
    pkg_date = datetime.datetime.utcnow()
    pkg_size = 12315153
    self.MockDoAnyAuth()
    self.MockQueryFilename(
        filename, blobstore_key=blobstore_key, pkgdata_sha256=supply_etag)
    self.mox.StubOutWithMock(pkgs.common, 'IsPanicModeNoPackages')
    pkgs.common.IsPanicModeNoPackages().AndReturn(False)
    self.mox.StubOutWithMock(pkgs.blobstore, 'BlobInfo')
    mock_blob_info = self.mox.CreateMockAnything()
    mock_blob_info.creation = pkg_date
    mock_blob_info.size = pkg_size
    self.mox.StubOutWithMock(pkgs.handlers, 'IsClientResourceExpired')
    self.mox.StubOutWithMock(pkgs.memcache, 'get')
    self.mox.StubOutWithMock(pkgs.memcache, 'set')

    self.request.headers.get('If-Modified-Since', '').AndReturn(mod_since_date)
    self.request.headers.get('If-None-Match', 0).AndReturn(0)
    self.request.headers.get('If-Match', 0).AndReturn(0)
    pkgs.memcache.get(blobinfo_memcache_key).AndReturn(None)
    pkgs.blobstore.BlobInfo.get(blobstore_key).AndReturn(mock_blob_info)
    pkgs.memcache.set(blobinfo_memcache_key, mock_blob_info, 300).AndReturn(
        None)
    pkgs.handlers.IsClientResourceExpired(pkg_date, mod_since_date).AndReturn(
        pkg_modified_since)
    if pkg_modified_since:
      self.response.headers['Content-Disposition'] = str(
          'attachment; filename=%s' % filename)
      self.response.headers['ETag'] = supply_etag
      self.response.headers['Last-Modified'] = pkg_date.strftime(
          pkgs.handlers.HEADER_DATE_FORMAT)
      self.response.headers['X-Download-Size'] = str(pkg_size)
      self.c.send_blob(blobstore_key).AndReturn(None)
    else:
      if supply_etag:
        self.response.headers['ETag'] = supply_etag
      self.response.set_status(httplib.NOT_MODIFIED)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def _GetFailureHelper(self,
      status,
      mod_since_date=None, pkg_etag=None,
      match_etag=None, nomatch_etag=None,
      is_expired=True):
    """Tests Packages.get()."""
    filename = 'good name.dmg'
    filename_quoted = 'good%20name.dmg'
    blobinfo_memcache_key = 'blobinfo_%s' % filename
    blobstore_key = 'fookey'
    pkg_date = datetime.datetime.utcnow()
    self.MockDoAnyAuth()
    self.MockQueryFilename(
        filename, blobstore_key=blobstore_key, pkgdata_sha256=pkg_etag)
    self.mox.StubOutWithMock(pkgs.common, 'IsPanicModeNoPackages')
    pkgs.common.IsPanicModeNoPackages().AndReturn(False)
    self.mox.StubOutWithMock(pkgs.blobstore, 'BlobInfo')
    mock_blob_info = self.mox.CreateMockAnything()
    mock_blob_info.creation = pkg_date
    self.mox.StubOutWithMock(pkgs.handlers, 'IsClientResourceExpired')
    self.mox.StubOutWithMock(pkgs.memcache, 'get')
    self.mox.StubOutWithMock(pkgs.memcache, 'set')

    self.request.headers.get('If-Modified-Since', '').AndReturn(mod_since_date)
    self.request.headers.get('If-None-Match', 0).AndReturn(nomatch_etag)
    self.request.headers.get('If-Match', 0).AndReturn(match_etag)
    pkgs.memcache.get(blobinfo_memcache_key).AndReturn(None)
    pkgs.blobstore.BlobInfo.get(blobstore_key).AndReturn(mock_blob_info)
    pkgs.memcache.set(blobinfo_memcache_key, mock_blob_info, 300).AndReturn(
        None)
    if not (nomatch_etag and not mod_since_date):
      pkgs.handlers.IsClientResourceExpired(
          pkg_date, mod_since_date).AndReturn(is_expired)
    if pkg_etag and status == httplib.NOT_MODIFIED:
      self.response.headers['ETag'] = str(pkg_etag)
    self.response.set_status(status)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetSuccessWherePackageNotModified(self):
    """Tests get() where the If-Modified-Since date is same as pkg date."""
    self.testGetSuccessHelper(pkg_modified_since=True)

  def testGetSuccessWherePackageWasModified(self):
    """Tests get() where the If-Modified-Since date is older than pkg date."""
    self.testGetSuccessHelper(pkg_modified_since=False, supply_etag='etag')

  def testGetSuccessWherePackageWasModifiedNoEtag(self):
    """Tests get() where the If-Modified-Since date is older than pkg date."""
    self.testGetSuccessHelper(pkg_modified_since=False, supply_etag=None)

  def testGet412WherePackageEtagNoMatch(self):
    """Tests get() where If-Match etag does not match package etag."""
    self._GetFailureHelper(
        412,
        mod_since_date='',
        pkg_etag=u'etag1',
        match_etag='etag2',
        is_expired=False)

  def testGet304WherePackageEtagMatch(self):
    """Tests get() where If-No-Match etag match package etag."""
    self._GetFailureHelper(
        304,
        mod_since_date='',
        pkg_etag=u'etag1',
        nomatch_etag='etag1',
        is_expired=False)

  def testGet404(self):
    """Tests Packages.get() where filename is not found."""
    filename = 'badname'
    self.MockDoAnyAuth(and_return='DoMunkiAuth session; no email attr')
    self.MockQueryFilename(filename, None)
    self.MockError(httplib.NOT_FOUND)

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testGetBlobInfoDoesNotExit(self):
    """Tests Packages.get() where the blob info doesn't exist."""
    filename = 'badname'
    blobstore_key = 'fookey'
    self.mox.StubOutWithMock(pkgs.blobstore, 'BlobInfo')
    self.mox.StubOutWithMock(pkgs.memcache, 'get')
    self.MockDoAnyAuth()
    self.MockQueryFilename(filename, blobstore_key)
    self.mox.StubOutWithMock(pkgs.common, 'IsPanicModeNoPackages')
    pkgs.common.IsPanicModeNoPackages().AndReturn(False)
    pkgs.memcache.get('blobinfo_%s' % filename).AndReturn(None)
    pkgs.blobstore.BlobInfo.get(blobstore_key).AndReturn(None)
    self.MockError(httplib.NOT_FOUND)

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testGetPanicModeNoPackages(self):
    """Tests Packages.get() where the blob info doesn't exist."""
    filename = 'badname'
    blobstore_key = 'fookey'
    self.mox.StubOutWithMock(pkgs.blobstore, 'BlobInfo')
    self.mox.StubOutWithMock(pkgs.memcache, 'get')
    self.MockDoAnyAuth()
    self.MockQueryFilename(filename, blobstore_key)
    self.mox.StubOutWithMock(pkgs.common, 'IsPanicModeNoPackages')
    pkgs.common.IsPanicModeNoPackages().AndReturn(True)
    self.MockError(httplib.SERVICE_UNAVAILABLE)

    self.mox.ReplayAll()
    self.c.get(filename)
    self.mox.VerifyAll()

  def testAdminAuth(self):
    """Tests Packages.get() where an admin user is requesting a pkg."""
    self.mox.StubOutWithMock(pkgs.auth, 'DoAnyAuth')
    self.mox.StubOutWithMock(pkgs.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(pkgs.auth, 'IsSupportUser')
    self.mox.StubOutWithMock(pkgs.urllib, 'unquote')

    mock_user = self.mox.CreateMockAnything()
    email = 'fooemail@example.com'
    pkgs.auth.DoAnyAuth().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    pkgs.auth.IsAdminUser(email).AndReturn(True)
    pkgs.auth.IsSupportUser(email).AndReturn(False)

    class StopTesting(Exception):
      """Class for only testing to a specific point in the code."""

    pkgs.urllib.unquote('anything').AndRaise(StopTesting)

    self.mox.ReplayAll()
    self.assertRaises(StopTesting, self.c.get, 'anything')
    self.mox.VerifyAll()

  def testSupportUserAuth(self):
    """Tests Packages.get() where a support group user is requesting a pkg."""
    self.mox.StubOutWithMock(pkgs.auth, 'DoAnyAuth')
    self.mox.StubOutWithMock(pkgs.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(pkgs.auth, 'IsSupportUser')
    self.mox.StubOutWithMock(pkgs.urllib, 'unquote')

    mock_user = self.mox.CreateMockAnything()
    email = 'fooemail@example.com'
    pkgs.auth.DoAnyAuth().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    pkgs.auth.IsAdminUser(email).AndReturn(False)
    pkgs.auth.IsSupportUser(email).AndReturn(True)

    class StopTesting(Exception):
      """Class for only testing to a specific point in the code."""

    pkgs.urllib.unquote('anything').AndRaise(StopTesting)

    self.mox.ReplayAll()
    self.assertRaises(StopTesting, self.c.get, 'anything')
    self.mox.VerifyAll()

  def testUserAuthButNotAdminOrSupportUser(self):
    """Tests Packages.get() where a non-admin user is requesting a pkg."""
    self.mox.StubOutWithMock(pkgs.auth, 'DoAnyAuth')
    self.mox.StubOutWithMock(pkgs.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(pkgs.auth, 'IsSupportUser')

    mock_user = self.mox.CreateMockAnything()
    email = 'fooemail@example.com'
    pkgs.auth.DoAnyAuth().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    pkgs.auth.IsAdminUser(email).AndReturn(False)
    pkgs.auth.IsSupportUser(email).AndReturn(False)

    self.mox.ReplayAll()
    self.assertRaises(pkgs.auth.IsAdminMismatch, self.c.get, 'anything')
    self.mox.VerifyAll()


class ClientRepairHandlerTest(test.RequestHandlerTest):
  """pkgs.ClientRepair handlers tests."""

  def GetTestClassInstance(self):
    return pkgs.ClientRepair()

  def GetTestClassModule(self):
    return pkgs

  def testGet(self):
    """Tests ClientRepair.get()."""
    session = 'session'
    track = 'stable'
    client_id = {'track': track}

    pkg1 = self.mox.CreateMockAnything()
    pkg1.filename = 'pkg1.ext'
    pkg1.catalogs = ['not a matching track']
    pkg2 = self.mox.CreateMockAnything()
    pkg2.filename = 'pkg2.ext'
    pkg2.catalogs = ['foo track', track, 'bar track']

    self.mox.StubOutWithMock(pkgs.handlers, 'GetClientIdForRequest')
    self.mox.StubOutWithMock(pkgs.Packages, 'get')

    self.MockDoAnyAuth(and_return=session)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('name =', 'munkitools').AndReturn([pkg1, pkg2])
    pkgs.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)
    pkgs.Packages.get(pkg2.filename).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()


class PkgsModuleTest(PackagesTest):
  """pkgs module level function tests."""

  def GetTestClassModule(self):
    return pkgs

  def GetTestClassInstance(self):
    return pkgs

  def testPackageExistsTrue(self):
    """Tests the success path for PackageExists()."""
    filename = 'goodname'
    self.mox.StubOutWithMock(pkgs.models.PackageInfo, 'get_by_key_name')
    pkgs.models.PackageInfo.get_by_key_name(filename).AndReturn(True)

    self.mox.ReplayAll()
    self.assertTrue(pkgs.PackageExists(filename))
    self.mox.VerifyAll()

  def testPackageExistsFalse(self):
    """Tests the success path for PackageExists()."""
    filename = 'badname'
    self.mox.StubOutWithMock(pkgs.models.PackageInfo, 'get_by_key_name')
    pkgs.models.PackageInfo.get_by_key_name(filename).AndReturn(None)

    self.mox.ReplayAll()
    self.assertFalse(pkgs.PackageExists(filename))
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
