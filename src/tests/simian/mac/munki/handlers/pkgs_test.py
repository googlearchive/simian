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

"""Munki pkgs module tests."""



import datetime
import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from simian.mac.common import test
from simian.mac.munki.handlers import pkgs


class PackagesTest(test.RequestHandlerTest):
  """pkgs module test helper class."""

  def MockQueryFilename(self, filename, blobstore_key=None):
    """Helper method to get a PackageInfo by filename."""
    if blobstore_key is None:
      mock_pkg = None
    else:
      mock_pkg = self.mox.CreateMockAnything()
      mock_pkg.blobstore_key = blobstore_key

    self.MockModelStaticBase(
        'PackageInfo', 'MemcacheWrappedGet', filename).AndReturn(mock_pkg)


class HandlersTest(PackagesTest):
  """pkgs.Packages handlers tests."""

  def GetTestClassInstance(self):
    return pkgs.Packages()

  def GetTestClassModule(self):
    return pkgs

  def testGetSuccessHelper(self, pkg_modified_since=True):
    """Tests Packages.get()."""
    filename = 'good name.dmg'
    filename_quoted = 'good%20name.dmg'
    blobinfo_memcache_key = 'blobinfo_%s' % filename
    blobstore_key = 'fookey'
    mod_since_date = 'foo str date'
    pkg_date = datetime.datetime.utcnow()
    self.MockDoAnyAuth()
    self.MockQueryFilename(filename, blobstore_key)
    self.mox.StubOutWithMock(pkgs.common, 'IsPanicModeNoPackages')
    pkgs.common.IsPanicModeNoPackages().AndReturn(False)
    self.mox.StubOutWithMock(pkgs.blobstore, 'BlobInfo')
    mock_blob_info = self.mox.CreateMockAnything()
    mock_blob_info.creation = pkg_date
    self.mox.StubOutWithMock(pkgs, 'IsPackageModifiedSince')
    self.mox.StubOutWithMock(pkgs.memcache, 'get')
    self.mox.StubOutWithMock(pkgs.memcache, 'set')
    self.MockSelf('send_blob')

    self.request.headers.get('If-Modified-Since', '').AndReturn(mod_since_date)
    pkgs.memcache.get(blobinfo_memcache_key).AndReturn(None)
    pkgs.blobstore.BlobInfo.get(blobstore_key).AndReturn(mock_blob_info)
    pkgs.memcache.set(blobinfo_memcache_key, mock_blob_info, 300).AndReturn(
        None)
    pkgs.IsPackageModifiedSince(pkg_date, mod_since_date).AndReturn(
        pkg_modified_since)
    if pkg_modified_since:
      self.response.headers['Last-Modified'] = pkg_date.strftime(
          pkgs.HEADER_DATE_FORMAT)
      self.c.send_blob(blobstore_key).AndReturn(None)
    else:
      self.response.set_status(304)

    self.mox.ReplayAll()
    self.c.get(filename_quoted)
    self.mox.VerifyAll()

  def testGetSuccessWherePackageNotModified(self):
    """Tests get() where the If-Modified-Since date is same as pkg date."""
    self.testGetSuccessHelper(pkg_modified_since=True)

  def testGetSuccessWherePackageWasModified(self):
    """Tests get() where the If-Modified-Since date is older than pkg date."""
    self.testGetSuccessHelper(pkg_modified_since=False)

  def testGet404(self):
    """Tests Packages.get() where filename is not found."""
    filename = 'badname'
    self.MockDoAnyAuth()
    self.MockQueryFilename(filename, None)
    self.MockError(404)

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
    self.MockError(404)

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
    self.MockError(503)

    self.mox.ReplayAll()
    self.c.get(filename)
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

  def testIsPackageModifiedSinceWithEmptyDate(self):
    """Tests IsPackageModifiedSince() with empty header str date."""
    self.assertTrue(pkgs.IsPackageModifiedSince(None, ''))

  def testPackageModifiedWithInvalidDate(self):
    """Tests IsPackageModifiedSince() with non-parsable header str date."""
    self.assertTrue(pkgs.IsPackageModifiedSince(None, 'date will not parse'))

  def testPackageModifiedMatchingDate(self):
    """Tests IsPackageModifiedSince() with matching header str date."""
    header_date_str = 'Wed, 06 Oct 2010 03:23:34 GMT'
    pkg_date = datetime.datetime(2010, 10, 06, 03, 23, 34)  # same date
    self.assertFalse(pkgs.IsPackageModifiedSince(pkg_date, header_date_str))

  def testPackageModifiedWherePackageDateNewer(self):
    """Tests IsPackageModifiedSince() with matching header str date."""
    header_date_str = 'Mon, 01 Jan 1930 01:00:00 GMT'
    pkg_date = datetime.datetime(2010, 10, 06, 03, 23, 34)  # later date
    self.assertTrue(pkgs.IsPackageModifiedSince(pkg_date, header_date_str))


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()