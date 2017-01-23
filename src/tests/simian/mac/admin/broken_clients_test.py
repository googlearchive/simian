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
import datetime

import mock
import stubout
import webtest

from google.apputils import basetest

from simian.mac import admin
from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test


def _ComputersListToUuidList(computers):
  return [c.uuid for c in computers]


class BrokenClientModuleTest(test.AppengineTest):

  def setUp(self):
    super(BrokenClientModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

  @mock.patch.object(auth, 'IsGroupMember', return_value=True)
  @mock.patch.object(admin.AdminHandler, 'Render')
  def testGet(self, render_mock, _):
    past = datetime.datetime.now() - datetime.timedelta(days=1)

    broken_uuid = 'uuid1'
    models.Computer(
        key_name=broken_uuid, preflight_datetime=past, uuid=broken_uuid).put()
    models.ComputerClientBroken(
        uuid=broken_uuid, details='42343243234', connections_off_corp=50,
        broken_datetimes=[datetime.datetime.now()]).put()

    toomany_preflight_uuid = 'toomany_preflight_since_postflight'
    models.Computer(
        uuid=toomany_preflight_uuid, connections_on_corp=40,
        preflight_count_since_postflight=50, postflight_datetime=past,
        preflight_datetime=datetime.datetime.now(),
    ).put()

    models.Computer(
        uuid='not_broken', connections_on_corp=40,
        preflight_count_since_postflight=3, postflight_datetime=past,
        preflight_datetime=datetime.datetime.now(),
    ).put()

    no_connections_uuid = 'client without connections'
    models.Computer(
        uuid=no_connections_uuid, preflight_count_since_postflight=6).put()

    self.testapp.get('/admin/brokenclients')

    args = test.GetArgFromCallHistory(render_mock, arg_index=1)

    self.assertEqual(
        [no_connections_uuid],
        _ComputersListToUuidList(args['zero_conn_computers']))

    self.assertEqual(
        [broken_uuid], _ComputersListToUuidList(args['py_computers']))

    self.assertEqual(
        [toomany_preflight_uuid],
        _ComputersListToUuidList(args['pf_computers']))

  @mock.patch.object(auth, 'IsGroupMember', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testMarkAsFixed(self, *_):
    broken_uuid = 'client_id'
    models.ComputerClientBroken(
        key_name=broken_uuid, uuid=broken_uuid, details='42343243234',
        connections_off_corp=50, broken_datetimes=[datetime.datetime.now()],
        fixed=False).put()

    self.testapp.post(
        '/admin/brokenclients', {'action': 'set_fixed', 'uuid': broken_uuid})

    self.assertTrue(
        models.ComputerClientBroken.get_by_key_name(broken_uuid).fixed)


if __name__ == '__main__':
  basetest.main()
