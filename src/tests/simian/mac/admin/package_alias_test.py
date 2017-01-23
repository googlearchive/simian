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


@mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
@mock.patch.object(auth, 'IsAdminUser', return_value=True)
class PackageAliasModuleTest(test.AppengineTest):

  def setUp(self):
    super(PackageAliasModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

  def testCreatePackageAlias(self, *_):
    aliasname = 'aliasname'
    pkgname = 'pkgname'
    models.PackageInfo(name=pkgname).put()

    self.testapp.post(
        '/admin/package_alias',
        {'create_package_alias': 1, 'package_alias': aliasname,
         'munki_pkg_name': pkgname}, status=httplib.FOUND)

    aliases = models.PackageAlias.all().fetch(None)
    self.assertEqual(1, len(aliases))
    self.assertEqual(aliasname, aliases[0].key().name())
    self.assertEqual(pkgname, aliases[0].munki_pkg_name)
    self.assertTrue(aliases[0].enabled)

  def testCreatePackageAliasPackageDoesNotExist(self, *_):
    aliasname = 'aliasname'
    pkgname = 'does_not_exist'
    self.testapp.post(
        '/admin/package_alias',
        {'create_package_alias': 1, 'package_alias': aliasname,
         'munki_pkg_name': pkgname}, status=httplib.FOUND)

    aliases = models.PackageAlias.all().fetch(None)
    self.assertEqual(0, len(aliases))

  def testDisablePackageAlias(self, *_):
    aliasname = 'aliasname'
    pkgname = 'pkgname'
    models.PackageAlias(key_name=aliasname, munki_pkg_name=pkgname).put()

    self.testapp.post(
        '/admin/package_alias',
        {'enabled': 0, 'key_name': aliasname}, status=httplib.OK)

    aliases = models.PackageAlias.all().fetch(None)
    self.assertEqual(1, len(aliases))
    self.assertFalse(aliases[0].enabled)

  @mock.patch.object(admin.AdminHandler, 'Render')
  def testDisplayMain(self, render_mock, *_):
    aliasname = 'aliasname'
    pkgname = 'pkgname'
    models.PackageAlias(key_name=aliasname, munki_pkg_name=pkgname).put()

    self.testapp.get('/admin/package_alias')

    args = test.GetArgFromCallHistory(render_mock, arg_index=1)
    self.assertEqual(1, len(args['package_aliases'].fetch(None)))


if __name__ == '__main__':
  basetest.main()
