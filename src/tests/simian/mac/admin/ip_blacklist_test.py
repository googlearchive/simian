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
import httplib


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
from simian.mac.common import util


class IpBlacklistModuleTest(test.AppengineTest):

  def setUp(self):
    super(IpBlacklistModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.AdminHandler, 'Render')
  def testGet(self, render_mock, _):
    data = {'192.168.1.1': 'zerocool'}
    models.KeyValueCache.MemcacheWrappedSet(
        'client_exit_ip_blocks', 'text_value', util.Serialize(data))

    self.testapp.get('/admin/ip_blacklist', status=httplib.OK)

    args = test.GetArgFromCallHistory(render_mock, arg_index=1)
    self.assertEquals(data.items(), args['list'])

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  def testGetAccessDenied(self, *_):
    self.testapp.get('/admin/ip_blacklist', status=httplib.FORBIDDEN)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testSet(self, *_):
    self.testapp.post(
        '/admin/ip_blacklist', {'item_0': '192.168.1.1', 'item_1': 'zerocool'},
        status=httplib.FOUND)
    self.assertEqual(
        {'192.168.1.1': 'zerocool'},
        util.Deserialize(models.KeyValueCache.MemcacheWrappedGet(
            'client_exit_ip_blocks', 'text_value')))


if __name__ == '__main__':
  basetest.main()
