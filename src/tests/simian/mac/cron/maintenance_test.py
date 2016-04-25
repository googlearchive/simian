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
"""maint module tests."""

import logging
import mox
import stubout

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.cron import maintenance as maint


class AuthSessionCleanupTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return maint.AuthSessionCleanup()

  def GetTestClassModule(self):
    return maint

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(maint.gaeserver, 'AuthSessionSimianServer')
    mock_ps = self.mox.CreateMockAnything()
    maint.gaeserver.AuthSessionSimianServer().AndReturn(mock_ps)

    mock_ps.ExpireAll().AndReturn(2)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()


class UpdateAverageInstallDurationsTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return maint.UpdateAverageInstallDurations()

  def GetTestClassModule(self):
    return maint

  def _testGetUpdatedDescriptionExistingDescWithAvgDuration(self):
    """Test _GetUpdatedDescription() with desc and avg duration text."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = 'Foo Bar\n\n%s' % avg_duration_text % (5490, 120)
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = 'Foo Bar\n\n%s' % avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def _testGetUpdatedDescriptionExistingDescWithoutAvgDuration(self):
    """Test _GetUpdatedDescription() with desc lacking avg durations text."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = 'Foo Bar'
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = 'Foo Bar\n\n%s' % avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def _testGetUpdatedDescriptionEmpty(self):
    """Test _GetUpdatedDescription() with an empty desc."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = ''
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def testGet(self):
    """Test get()."""
    pkginfo1 = self.mox.CreateMockAnything()
    pkginfo1.name = 'name1'
    pkginfo1.filename = 'filename1'
    pkginfo1.plist = 'plist1'
    pkginfo1.version = '1.2.3'
    pkg1_munki_name = '%s-%s' % (pkginfo1.name, pkginfo1.version)
    pkginfo1.munki_name = pkg1_munki_name
    pkg1_lock = 'pkgsinfo_%s' % pkginfo1.filename
    mock_pl1 = self.mox.CreateMockAnything()
    pkginfo1.plist = mock_pl1

    pkginfos = [pkginfo1]

    install_counts = {
        pkg1_munki_name: {
            'install_count': 3,
            'applesus': True,
            'duration_count': 2,
            'duration_total_seconds': 50,
            'duration_seconds_avg': int((50)/2),
         },
    }

    pkg1_avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT % (
        install_counts[pkg1_munki_name]['duration_count'],
        install_counts[pkg1_munki_name]['duration_seconds_avg'])
    pkg1_desc = 'This pkg is cool!'
    pkg1_desc_updated = '%s\n\n%s' % (pkg1_desc, pkg1_avg_duration_text)

    # Start with the description lacking avg duration text.
    pkginfo1.description = pkg1_desc

    self.mox.StubOutWithMock(maint.models.ReportsCache, 'GetInstallCounts')
    self.mox.StubOutWithMock(maint.models.PackageInfo, 'all')
    self.mox.StubOutWithMock(maint.gae_util, 'ObtainLock')
    self.mox.StubOutWithMock(maint.gae_util, 'ReleaseLock')
    self.mox.StubOutWithMock(maint.models.Catalog, 'all')
    self.mox.StubOutWithMock(maint.models.Catalog, 'Generate')

    maint.models.ReportsCache.GetInstallCounts().AndReturn(
        (install_counts, None))
    maint.models.PackageInfo.all().AndReturn(pkginfos)
    maint.gae_util.ObtainLock(pkg1_lock, timeout=5.0).AndReturn(True)
    mock_pl1.__getitem__('description').AndReturn(pkg1_desc)
    mock_pl1.__getitem__('description').AndReturn(pkg1_desc_updated)
    pkginfo1.put().AndReturn(None)
    maint.gae_util.ReleaseLock(pkg1_lock).AndReturn(None)

    delay = 0
    for track in maint.common.TRACKS:
      delay += 5
      maint.models.Catalog.Generate(track, delay=delay)

    self.mox.ReplayAll()
    self.c.get()
    self.assertEqual(pkginfo1.description, pkg1_desc_updated)
    self.mox.VerifyAll()


class VerifyPackagesCleanupTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return maint.VerifyPackages()

  def GetTestClassModule(self):
    return maint

  def MockPackageInfoQuery(self, blobstore_key, return_value=None, sleep=0):
    """Mocks a PackageInfo query filtering with a given mock blob and key."""
    mock_query = self.mox.CreateMockAnything()
    maint.models.PackageInfo.all().AndReturn(mock_query)
    mock_query.filter('blobstore_key =', blobstore_key).AndReturn(mock_query)
    mock_query.get().AndReturn(return_value)
    if sleep:
      maint.time.sleep(sleep).AndReturn(None)

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(maint.models, 'PackageInfo')
    self.mox.StubOutWithMock(maint.blobstore, 'BlobInfo')
    self.mox.StubOutWithMock(maint.time, 'sleep')
    self.mox.StubOutWithMock(maint.mail, 'SendMail')
    blobstore_key_good = 'goodkey'
    blobstore_key_bad = 'badkey'
    filename_bad = 'badfilename'

    # verify PackageInfo entities have Blobstore blobs.
    mock_pkginfo_good = self.mox.CreateMockAnything()
    mock_pkginfo_bad = self.mox.CreateMockAnything()
    mock_pkginfo_good.blobstore_key = blobstore_key_good
    mock_pkginfo_bad.blobstore_key = blobstore_key_bad
    mock_pkginfo_bad.filename = filename_bad
    mock_pkginfo_bad.mtime = maint.datetime.datetime(1970, 1, 1)
    pkginfos = [mock_pkginfo_good, mock_pkginfo_bad]
    maint.models.PackageInfo.all().AndReturn(pkginfos)
    maint.blobstore.BlobInfo.get(
        mock_pkginfo_good.blobstore_key).AndReturn(True)
    maint.blobstore.BlobInfo.get(
        mock_pkginfo_bad.blobstore_key).AndReturn(None)

    maint.mail.SendMail(
        mox.IgnoreArg(), 'Package is lacking a file: %s' % filename_bad,
        mox.IgnoreArg()).AndReturn(None)

    # verify Blobstore blobs are not orphaned.
    blob_good = self.mox.CreateMockAnything()
    blob_bad = self.mox.CreateMockAnything()
    blob_bad.filename = filename_bad
    blobs = [blob_good, blob_bad]
    maint.blobstore.BlobInfo.all().AndReturn(blobs)
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

    maint.mail.SendMail(
        mox.IgnoreArg(), 'Orphaned Blob in Blobstore: %s' % filename_bad,
        mox.IgnoreArg()).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
