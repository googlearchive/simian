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
import json


import mock
import stubout
import webtest

from google.apputils import app
from google.apputils import basetest

from simian.mac import admin
from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.common import auth
from tests.simian.mac.common import test


class AclGroupsModuleTest(test.AppengineTest):

  def setUp(self):
    super(AclGroupsModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

  def testPostWithoutToken(self):
    resp = self.testapp.post('/admin/acl_groups', status=httplib.BAD_REQUEST)
    self.assertIn('Invalid XSRF token.', resp.body)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.template, 'render', return_value='html:)')
  def testPostWithValidToken(self, render_mock, _):
    newuser = 'zerocool@example.com'
    self.testapp.get('/admin/acl_groups', status=httplib.OK)
    params = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': params['xsrf_token'],
        'item_0': [newuser]
    }
    self.testapp.post(
        '/admin/acl_groups/support_users', params, status=httplib.FOUND)

    users = json.loads(
        models.KeyValueCache.MemcacheWrappedGet('support_users', 'text_value'))
    self.assertEqual([newuser], users)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
