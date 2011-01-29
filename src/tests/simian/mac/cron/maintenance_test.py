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

"""maintenance module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.cron import maintenance


class MaintenanceModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class AuthSessionCleanupTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(maintenance.gaeserver, 'AuthSessionSimianServer')
    mock_ps = self.mox.CreateMockAnything()
    maintenance.gaeserver.AuthSessionSimianServer().AndReturn(mock_ps)

    mock_ps.ExpireAll().AndReturn(2)

    asc = maintenance.AuthSessionCleanup()
    self.mox.ReplayAll()
    asc.get()
    self.mox.VerifyAll()


class VerifyPackagesCleanupTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def MockPackageInfoQuery(self, blobstore_key, return_value=None, sleep=0):
    """Mocks a PackageInfo query filtering with a given mock blob and key."""
    mock_query = self.mox.CreateMockAnything()
    maintenance.models.PackageInfo.all().AndReturn(mock_query)
    mock_query.filter('blobstore_key =', blobstore_key).AndReturn(mock_query)
    mock_query.get().AndReturn(return_value)
    if sleep:
      maintenance.time.sleep(sleep).AndReturn(None)

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(maintenance.models, 'PackageInfo')
    self.mox.StubOutWithMock(maintenance.blobstore, 'BlobInfo')
    self.mox.StubOutWithMock(maintenance.logging, 'critical')
    self.mox.StubOutWithMock(maintenance.time, 'sleep')
    blobstore_key_good = 'goodkey'
    blobstore_key_bad = 'badkey'
    filename_bad = 'badfilename'

    # verify PackageInfo entities have Blobstore blobs.
    mock_pkginfo_good = self.mox.CreateMockAnything()
    mock_pkginfo_bad = self.mox.CreateMockAnything()
    mock_pkginfo_good.blobstore_key = blobstore_key_good
    mock_pkginfo_bad.blobstore_key = blobstore_key_bad
    mock_pkginfo_bad.filename = filename_bad
    pkginfos = [mock_pkginfo_good, mock_pkginfo_bad]
    maintenance.models.PackageInfo.all().AndReturn(pkginfos)
    maintenance.blobstore.BlobInfo.get(
        mock_pkginfo_good.blobstore_key).AndReturn(True)
    maintenance.blobstore.BlobInfo.get(
        mock_pkginfo_bad.blobstore_key).AndReturn(None)
    maintenance.logging.critical('PackageInfo missing Blob: %s', filename_bad)

    # verify Blobstore blobs are not orphaned.
    blob_good = self.mox.CreateMockAnything()
    blob_bad = self.mox.CreateMockAnything()
    blob_bad.filename = filename_bad
    blobs = [blob_good, blob_bad]
    maintenance.blobstore.BlobInfo.all().AndReturn(blobs)
    # good blob
    blob_good.key().AndReturn(blobstore_key_good)
    self.MockPackageInfoQuery(blobstore_key_good, return_value='non None')
    # bad blob
    blob_bad.key().AndReturn(blobstore_key_bad)
    self.MockPackageInfoQuery(blobstore_key_bad, sleep=1)  # attempt 1
    self.MockPackageInfoQuery(blobstore_key_bad, sleep=1)  # attempt 2
    self.MockPackageInfoQuery(blobstore_key_bad, sleep=1)  # attempt 3
    self.MockPackageInfoQuery(blobstore_key_bad, sleep=1)  # attempt 4
    self.MockPackageInfoQuery(blobstore_key_bad)  # attempt 5
    maintenance.logging.critical(
        'Orphaned Blob %s: %s', blob_bad.filename, blobstore_key_bad)

    vp = maintenance.VerifyPackages()
    self.mox.ReplayAll()
    vp.get()
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()