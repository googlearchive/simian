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
import httplib
import uuid
import mock
import stubout

from google.apputils import app
from google.apputils import basetest

from simian.mac import models
from simian.mac.admin import host
from simian.mac.admin import main as gae_main
from simian.mac.common import auth
from tests.simian.mac.common import test


class HostModuleTest(test.AppengineTest):

  def setUp(self):
    super(HostModuleTest, self).setUp()

    self.common_serial = str(uuid.uuid4())
    models.Computer(
        active=True, hostname='host1', serial=self.common_serial,
        uuid='UUID1', key_name='UUID1', owner='zaspire', client_version='2.3.1',
        os_version='10.11', site='NYC', track='stable',
        config_track='stable', connections_on_corp=1, connections_off_corp=0,
        uptime=90000.0, root_disk_free=0, user_disk_free=10).put()

    models.Computer(
        active=True, hostname='new-host1', serial=self.common_serial,
        uuid='NEWUUID1==', key_name='NEWUUID1==', owner='user',
        os_version='10.11', site='NYC', track='stable',
        config_track='stable', connections_on_corp=1, connections_off_corp=0,
        uptime=90000.0, root_disk_free=0, user_disk_free=10,
        client_version='2.7.1').put()

    models.Computer(
        active=True, hostname='host10', serial=str(uuid.uuid4()),
        uuid='UUID2', key_name='UUID2', owner='user',
        client_version='2.3.2', os_version='10.11', site='MTV',
        track='stable', config_track='stable',
        connections_on_corp=1, connections_off_corp=1,
        uptime=90000.0, root_disk_free=0, user_disk_free=10).put()

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.dict(host.settings.__dict__, {
      'ALLOW_SELF_REPORT': True, 'AUTH_DOMAIN': 'example.com',
      'CLIENT_SITE_ENABLED': False})
  @mock.patch.object(host.Host, 'Render')
  def testSelfReport(self, render, *_):
    resp = gae_main.app.get_response('/admin/host/UUID2/')

    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(httplib.OK, resp.status_int)
    self.assertTrue(params['self_report'])

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.dict(host.settings.__dict__, {
      'ALLOW_SELF_REPORT': True, 'AUTH_DOMAIN': 'example.com',
      'CLIENT_SITE_ENABLED': False})
  def testSelfReportWithWrongMachineAccessDenied(self, *_):
    resp = gae_main.app.get_response(
        '/admin/host/UUID1/')

    self.assertEqual(httplib.FORBIDDEN, resp.status_int)

  @mock.patch.object(auth, 'IsGroupMember', return_value=True)
  @mock.patch.dict(host.settings.__dict__, {'CLIENT_SITE_ENABLED': False})
  @mock.patch.object(host.Host, 'Render')
  def testHaveEntriesWithSameSerial(self, render, *_):
    resp = gae_main.app.get_response('/admin/host/NEWUUID1==/')

    self.assertEqual(httplib.OK, resp.status_int)
    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(1, len(params['duplicates']))
    other = params['duplicates'][0]
    self.assertEqual(self.common_serial, other.serial)
    self.assertEqual('UUID1', other.uuid)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
