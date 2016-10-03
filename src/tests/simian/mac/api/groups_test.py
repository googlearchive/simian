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
"""Groups API module tests."""

import httplib

import mock
import stubout
import webtest

from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest

from simian.mac import models
from simian.mac.api import groups
from simian.mac.api import urls as gae_main
from simian.mac.common import auth


class GroupsAPITest(basetest.TestCase):

  def setUp(self):
    super(GroupsAPITest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='user@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()

    self.headers = {'X-Simian-API-Info-Key': groups.API_INFO_KEY}
    models.Group(key_name='test group', users=['user1', 'user4']).put()
    models.Group(key_name='test group2', users=['user1', 'user2']).put()

  def tearDown(self):
    super(GroupsAPITest, self).tearDown()
    self.testbed.deactivate()

  def testGetWithGroup(self):
    """Tests get() with specific group specified."""
    url = '/api/groups?group=test group&key=%s' % groups.API_INFO_KEY
    resp = self.testapp.get(url, headers=self.headers, status=httplib.OK)
    self.assertItemsEqual(['user1', 'user4'], resp.json)

  def testGetWithAllGroups(self):
    """Tests get() with no group specified."""
    url = '/api/groups?key=%s' % groups.API_INFO_KEY
    resp = self.testapp.get(url, headers=self.headers, status=httplib.OK)
    self.assertItemsEqual(models.Group.GetAllGroupNames(), resp.json)

  @mock.patch.object(auth, 'DoOAuthAuth', return_value='user@example.com')
  def testPost(self, _):
    """Tests post()."""
    params = {
        'group': 'test group3',
        'members': 'user7,user8',
    }

    self.testapp.post(
        '/api/groups', params, headers=self.headers, status=httplib.OK)
    self.assertIn('test group3', models.Group.GetAllGroupNames())
    self.assertItemsEqual(
        ['user7', 'user8'], models.Group.get_by_key_name('test group3').users)

  @mock.patch.object(auth, 'DoOAuthAuth', return_value='user@example.com')
  def testPut(self, _):
    """Tests put()."""
    params = {
        'group': 'test group',
        'members': 'user4,user8',
    }

    self.testapp.put(
        '/api/groups', params, headers=self.headers, status=httplib.OK)
    self.assertItemsEqual(
        ['user1', 'user4', 'user8'],
        models.Group.get_by_key_name('test group').users)

  @mock.patch.object(auth, 'DoOAuthAuth', return_value='user@example.com')
  def testDelete(self, _):
    """Tests delete()."""
    self.testapp.delete(
        '/api/groups/test group', headers=self.headers, status=httplib.OK)
    self.assertNotIn('test group', models.Group.GetAllGroupNames())


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
