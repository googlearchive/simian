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


import mox
import stubout

from google.apputils import basetest

# Import and load mock modules before importing preflight.
# pylint: disable=g-bad-import-order
# pylint: disable=g-import-not-at-top
from tests.simian.mac.client import munkicommon_mock
munkicommon_mock.LoadMockModules()

from simian.mac.client import preflight


class PreflightTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)

  def tearDown(self):
    self.mox.UnsetStubs()

  def testRunPreflight(self):
    client_id = {
        'mgmt_enabled': True,
        'on_corp': '1',
        'owner': 'crosbym',
        'track': 'testing',
        'uptime': 1211865.2038304806,
        'uuid': 'abcd4077-0b34-4572-ba91-cc7aad032b5c',
    }
    feedback = {
        'upload_logs': 1,
        'pkill_installd': 1,
        'repair': 1,
        'logging_level': 2,
    }
    prefs = {'SoftwareRepoURL': 'test_url'}
    secure_config = {'track': 'testing'}
    user_settings = {'setting1': 'value1'}

    self.mox.StubOutWithMock(preflight, 'NoteLastRun')
    self.mox.StubOutWithMock(
        preflight.munkicommon, 'ManagedInstallsPreferences')
    self.mox.StubOutWithMock(
        preflight.flight_common, 'GetClientIdentifier')
    self.mox.StubOutWithMock(
        preflight.munkicommon, 'SecureManagedInstallsPreferences')
    self.mox.StubOutWithMock(
        preflight.flight_common, 'GetUserSettings')
    self.mox.StubOutWithMock(
        preflight, 'LoginToServer')
    self.mox.StubOutWithMock(
        preflight, 'WriteRootCaCerts')
    self.mox.StubOutWithMock(
        preflight.flight_common, 'UploadClientLogFiles')
    self.mox.StubOutWithMock(
        preflight.flight_common, 'RepairClient')
    self.mox.StubOutWithMock(
        preflight, 'CreateEmptyDirectory')
    self.mox.StubOutWithMock(
        preflight.flight_common, 'UploadAllManagedInstallReports')
    mock_client = self.mox.CreateMockAnything()

    preflight.NoteLastRun().AndReturn(None)
    preflight.munkicommon.ManagedInstallsPreferences().AndReturn(prefs)
    preflight.munkicommon.SecureManagedInstallsPreferences().AndReturn(
        secure_config)
    preflight.flight_common.GetClientIdentifier('auto').AndReturn(client_id)
    preflight.flight_common.GetUserSettings().AndReturn(user_settings)
    preflight.LoginToServer(
        secure_config, client_id, user_settings, None).AndReturn((
            mock_client, feedback))
    preflight.WriteRootCaCerts(mock_client)
    preflight.flight_common.UploadClientLogFiles(mock_client)
    preflight.flight_common.RepairClient()
    preflight.CreateEmptyDirectory().AndReturn('/test/path')
    preflight.flight_common.UploadAllManagedInstallReports(
        mock_client, client_id['on_corp'])

    self.mox.ReplayAll()
    preflight.RunPreflight('auto')
    self.mox.VerifyAll()


if __name__ == '__main__':
  basetest.main()
