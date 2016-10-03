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
"""groups module tests."""

import httplib


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


@mock.patch.object(auth, 'IsAdminUser', return_value=True)
@mock.patch.object(admin.template, 'render', return_value='html:)')
class AdminGroupsTest(test.AppengineTest):

  def setUp(self):
    super(AdminGroupsTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

    models.Group(key_name='test group', users=['user1', 'user4']).put()
    models.Group(key_name='test group2', users=['user1', 'user2']).put()

  def testGet(self, render_mock, *unused_args):
    """Test get()."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)
    self.assertIn('test group', [x.key().name() for x in render_dict['groups']])

  def testPostCreate(self, render_mock, *unused_args):
    """Test post() create action."""

    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group3',
        'action': 'create',
        'user': 'user5',
    }

    resp = self.testapp.post('/admin/groups', params, status=httplib.FOUND)
    redirect_url = '/admin/groups?msg=Group successfully saved.'

    self.assertTrue(resp.location.endswith(redirect_url))
    self.assertIn('user5', models.Group.get_by_key_name('test group3').users)

  def testPostDeleteNoManMods(self, render_mock, *unused_args):
    """Test post() delete action, no manifest modifications."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group',
        'action': 'delete',
    }

    resp = self.testapp.post('/admin/groups', params, status=httplib.FOUND)
    redirect_url = '/admin/groups?msg=Group successfully deleted.'

    self.assertTrue(resp.location.endswith(redirect_url))
    self.assertNotIn('test group', models.Group.GetAllGroupNames())

  def testPostDeleteNoManModsNoGroup(self, render_mock, *unused_args):
    """Test post() delete action, no manifest modifications, no group."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group42',
        'action': 'delete',
    }

    self.testapp.post('/admin/groups', params, status=httplib.NOT_FOUND)

  def testPostDeleteWithManMods(self, render_mock, *unused_args):
    """Test post() delete action, manifiest modifications exist."""
    models.GroupManifestModification.GenerateInstance(
        mod_type='group', target='test group', munki_pkg_name='Firefox').put()

    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group',
        'action': 'delete',
    }

    resp = self.testapp.post('/admin/groups', params, status=httplib.FOUND)
    redirect_url = ("/admin/groups?msg=Group not deleted as it's being used "
                    "for Manifest Modifications.")

    self.assertTrue(resp.location.endswith(redirect_url))
    self.assertIn('test group', models.Group.GetAllGroupNames())

  def testPostChangeAdd(self, render_mock, *unused_args):
    """Test post() change action, add user."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group',
        'action': 'change',
        'user': 'user7',
        'add': '1'
    }

    resp = self.testapp.post('/admin/groups', params, status=httplib.FOUND)
    redirect_url = '/admin/groups?msg=Group successfully modified.'

    self.assertTrue(resp.location.endswith(redirect_url))
    self.assertIn('user7', models.Group.get_by_key_name('test group').users)

  def testPostChangeRemove(self, render_mock, *unused_args):
    """Test post() change action, remove user."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group',
        'action': 'change',
        'user': 'user4',
        'add': '0'
    }

    resp = self.testapp.post('/admin/groups', params, status=httplib.FOUND)
    redirect_url = '/admin/groups?msg=Group successfully modified.'

    self.assertTrue(resp.location.endswith(redirect_url))
    self.assertNotIn('user4', models.Group.get_by_key_name('test group').users)

  def testPostChangeNoGroup(self, render_mock, *unused_args):
    """Test post() change action, group doesn't exist."""
    self.testapp.get('/admin/groups', status=httplib.OK)
    render_dict = test.GetArgFromCallHistory(render_mock, arg_index=1)

    params = {
        'xsrf_token': render_dict['xsrf_token'],
        'group': 'test group42',
        'action': 'change',
        'user': 'user4',
        'add': '1'
    }

    self.testapp.post('/admin/groups', params, status=httplib.NOT_FOUND)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
