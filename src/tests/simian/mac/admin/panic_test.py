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
"""panic module tests."""

import httplib
import logging


import mock
import stubout
import webtest

from google.apputils import app
from google.apputils import basetest
import tests.appenginesdk
from simian.mac import admin
from simian.mac.admin import main as gae_main
from simian.mac.admin import panic
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test
from simian.mac.munki import common


@mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
class AdminPanicTest(test.AppengineTest):

  def setUp(self):
    super(AdminPanicTest, self).setUp()

    self.testapp = webtest.TestApp(gae_main.app)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.template, 'render', return_value='html:)')
  def testGet(self, render_mock, *_):
    self.testapp.get('/admin/panic', status=httplib.OK)

    modes = []
    for mode in panic.common.PANIC_MODES:
      modes.append({'name': mode, 'enabled': False})

    render_mock.assert_called_once()
    self.assertEqual(
        modes, test.GetArgFromCallHistory(render_mock, arg_index=1)['modes'])

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.template, 'render', return_value='html:)')
  def testPost(self, render_mock, *_):
    mode = 'Mod1'
    self.testapp.post('/admin/panic', {'mode': mode, 'enabled': 'enable'})

    render_mock.assert_called_once()
    self.assertTrue(
        test.GetArgFromCallHistory(
            render_mock).endswith('panic_set_verify.html'))
    self.assertEqual(
        {'name': mode, 'enabled': 'enable'},
        test.GetArgFromCallHistory(render_mock, arg_index=1)['mode'])

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testPostWhenVerifyEnable(self, *_):
    mode = 'no_packages'

    resp = self.testapp.post(
        '/admin/panic', {'mode': mode, 'enabled': 'enable', 'verify': 1},
        status=httplib.FOUND)

    self.assertTrue(resp.headers['Location'].endswith('/admin/panic'))
    self.assertTrue(common.IsPanicMode(mode))

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testPostWhenVerifyDisable(self, *_):
    mode = 'no_packages'
    common.SetPanicMode(mode, True)

    resp = self.testapp.post(
        '/admin/panic', {'mode': mode, 'enabled': 'disable', 'verify': 1},
        status=httplib.FOUND)

    self.assertTrue(resp.headers['Location'].endswith('/admin/panic'))
    self.assertFalse(common.IsPanicMode(mode))

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testPostWhenInvalidMode(self, *_):
    mode = 'modezzz'
    self.testapp.post(
        '/admin/panic', {'mode': mode, 'enabled': 'disable', 'verify': 1},
        status=httplib.BAD_REQUEST)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testPostWhenInvalidEnabled(self, *_):
    mode = 'no_packages'
    enabled = 'enablzzZZZe'
    common.SetPanicMode(mode, True)

    self.testapp.post(
        '/admin/panic', {'mode': mode, 'enabled': enabled, 'verify': 1},
        status=httplib.BAD_REQUEST)

  def testPostAccessDenied(self, *_):
    mode = 'no_packages'
    common.SetPanicMode(mode, True)

    self.testapp.post(
        '/admin/panic', {'mode': mode, 'enabled': 'disable', 'verify': 1},
        status=httplib.FORBIDDEN)

  def testGetAccessDenied(self, *_):
    self.testapp.get('/admin/panic', status=httplib.FORBIDDEN)


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
