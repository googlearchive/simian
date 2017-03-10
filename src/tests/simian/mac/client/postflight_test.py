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

from simian.mac.client import postflight


class PostflightTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)

  def tearDown(self):
    self.mox.UnsetStubs()

  def testRunPostflight(self):
    pkgs_to_install = ['pkg1', 'pkg2']
    updates_to_install = ['update1', 'update2']
    client_id = {
        'uuid': 'abcd4077-0b34-4572-ba91-cc7aad032b5c',
        'on_corp': '1',
    }
    expected_report = {
        'apple_updates_to_install': updates_to_install,
        'client_id': 'fake_string',
        'pkgs_to_install': pkgs_to_install,
    }
    mock_url = 'http://test-url'
    mock_client = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(postflight.flight_common, 'GetServerURL')
    self.mox.StubOutWithMock(postflight.flight_common, 'GetAuth1Token')
    self.mox.StubOutWithMock(postflight.flight_common, 'GetClientIdentifier')
    self.mox.StubOutWithMock(
        postflight.flight_common, 'GetRemainingPackagesToInstall')
    self.mox.StubOutWithMock(postflight.mac_client, 'SimianAuthClient')
    # mock out DictToStr because of hash randomization.
    self.mox.StubOutWithMock(postflight.flight_common, 'DictToStr')
    self.mox.StubOutWithMock(
        postflight.flight_common, 'UploadAllManagedInstallReports')
    self.mox.StubOutWithMock(postflight.munkicommon, 'cleanUpTmpDir')
    self.mox.StubOutWithMock(postflight, 'IsAppInPlace')
    self.mox.StubOutWithMock(postflight, 'NoteLastSuccess')

    postflight.flight_common.GetServerURL().AndReturn(mock_url)
    postflight.flight_common.GetAuth1Token().AndReturn('fake_auth')
    postflight.flight_common.GetClientIdentifier('auto').AndReturn(client_id)
    postflight.mac_client.SimianAuthClient(
        'abcd4077-0b34-4572-ba91-cc7aad032b5c',
        hostname=mock_url).AndReturn(mock_client)
    mock_client.SetAuthToken('fake_auth')
    postflight.flight_common.GetClientIdentifier('auto').AndReturn(client_id)
    postflight.flight_common.GetRemainingPackagesToInstall().AndReturn((
        pkgs_to_install, updates_to_install))
    postflight.flight_common.DictToStr(client_id).AndReturn('fake_string')
    mock_client.PostReport('postflight', expected_report)
    postflight.flight_common.UploadAllManagedInstallReports(
        mock_client, client_id['on_corp'])
    postflight.IsAppInPlace().AndReturn(True)
    mock_client.LogoutAuthToken().AndReturn(True)
    postflight.munkicommon.cleanUpTmpDir()
    postflight.NoteLastSuccess().AndReturn(None)

    self.mox.ReplayAll()
    postflight.RunPostflight('auto')
    self.mox.VerifyAll()


if __name__ == '__main__':
  basetest.main()
