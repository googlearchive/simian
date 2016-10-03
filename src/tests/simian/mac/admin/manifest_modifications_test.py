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
import mock
import stubout

from google.appengine.api import users

from google.apputils import app
from google.apputils import basetest

from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.admin import manifest_modifications
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test


@mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
class ManifestModificationsModuleTest(test.AppengineTest):

  def setUp(self):
    super(ManifestModificationsModuleTest, self).setUp()

    models.OwnerManifestModification(
        owner='zaspire', enabled=False, install_types=['managed_installs'],
        value='fooinstallname', manifests=['unstable', 'testing'],
        target='target', key_name='1234', user=users.User('user@example.com'),
        ).put()

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testAdminPageLoad(self, *_):
    resp = gae_main.app.get_response('/admin/manifest_modifications')
    self.assertEqual(httplib.OK, resp.status_int)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  def testAccessDenied(self, *_):
    resp = gae_main.app.get_response('/admin/manifest_modifications')
    self.assertEqual(httplib.FORBIDDEN, resp.status_int)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(manifest_modifications.ManifestModifications, 'Render')
  def testDisplayMainAsAdmin(self, render, *_):
    resp = gae_main.app.get_response('/admin/manifest_modifications')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(1, len(params['mods']))
    self.assertEqual(True, params['can_add_manifest_mods'])
    self.assertEqual(0, len(params['error']))

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(manifest_modifications.ManifestModifications, 'Render')
  def testOwnerFilterEmptyResult(self, render, *_):
    resp = gae_main.app.get_response(
        '/admin/manifest_modifications?filter_field=target&'
        'filter_value=notfound')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(0, len(params['mods']))

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(manifest_modifications.ManifestModifications, 'Render')
  def testUserFilter(self, render, *_):
    resp = gae_main.app.get_response(
        '/admin/manifest_modifications?filter_field=admin&'
        'filter_value=user@example.com')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(1, len(params['mods']))

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(manifest_modifications.ManifestModifications, 'Render')
  def testDisplayMainWithIncorrectTag(self, render, *_):
    resp = gae_main.app.get_response('/admin/manifest_modifications?mod_type=b')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertEqual(1, len(params['mods']))
    self.assertGreater(len(params['error']), 0)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testDelete(self, *_):
    key = str(models.OwnerManifestModification.all().fetch(99)[0].key())

    resp = gae_main.app.get_response(
        '/admin/manifest_modifications', {'REQUEST_METHOD': 'POST'},
        POST={'delete': '1', 'key': key})

    self.assertEqual(httplib.OK, resp.status_int)
    self.assertEqual(0, len(models.OwnerManifestModification.all().fetch(99)))

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testSetEnabled(self, *_):
    mod = models.OwnerManifestModification.all().fetch(99)[0]
    key = str(mod.key())
    self.assertFalse(mod.enabled)

    resp = gae_main.app.get_response(
        '/admin/manifest_modifications', {'REQUEST_METHOD': 'POST'},
        POST={'enabled': '1', 'key': key})

    self.assertEqual(httplib.OK, resp.status_int)
    mod = models.OwnerManifestModification.all().fetch(99)[0]
    self.assertTrue(mod.enabled)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testAdd(self, *_):
    models.PackageInfo = mock.MagicMock()
    models.PackageInfo.GetManifestModPkgNames.return_value = ['mock_pkg_name']

    resp = gae_main.app.get_response(
        '/admin/manifest_modifications', {'REQUEST_METHOD': 'POST'},
        POST={
            'add_manifest_mod': '1', 'mod_type': 'uuid',
            'install_types': 'managed_installs', 'target': 'target',
            'manifests': 'testing', 'munki_pkg_name': 'mock_pkg_name',
            })

    mods = models.UuidManifestModification.all().fetch(99)

    self.assertEqual(httplib.FOUND, resp.status_int)
    self.assertEqual(1, len(mods))
    self.assertEqual(['testing'], mods[0].manifests)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testAddMultipleTargets(self, *_):
    models.PackageInfo = mock.MagicMock()
    models.PackageInfo.GetManifestModPkgNames.return_value = ['mock_pkg_name']

    resp = gae_main.app.get_response(
        '/admin/manifest_modifications', {'REQUEST_METHOD': 'POST'},
        POST={
            'add_manifest_mod': '1', 'mod_type': 'uuid',
            'install_types': 'managed_installs',
            'target': 'target1, target2 , target3,',
            'manifests': 'testing', 'munki_pkg_name': 'mock_pkg_name',
            })

    mods = models.UuidManifestModification.all().fetch(99)

    self.assertEqual(httplib.FOUND, resp.status_int)
    self.assertEqual(3, len(mods))
    self.assertEqual(
        ['target1', 'target2', 'target3'],
        sorted([mod.target for mod in mods]))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
