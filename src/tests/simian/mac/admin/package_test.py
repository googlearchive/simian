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
import unittest
import mock
import stubout

import webtest

from simian.mac import admin
from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.admin import package
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test
from simian.mac.models import munki
from simian.mac.models import settings as settings_model


@mock.patch.object(munki.Catalog, 'Generate', return_value=True)
@mock.patch.object(munki.Manifest, 'Generate', return_value=True)
class PackageInfoProposalTest(test.AppengineTest):
  """Test PackageInfoProposal class."""

  def setUp(self):
    super(PackageInfoProposalTest, self).setUp()

    self.testapp = webtest.TestApp(gae_main.app)

    self.test_plist = '''<?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>autoremove</key>
        <false/>
        <key>catalogs</key>
        <array>
          <string>unstable</string>
        </array>
        <key>description</key>
        <string>test package</string>
        <key>display_name</key>
        <string>testpackage</string>
        <key>installed_size</key>
        <integer>1</integer>
        <key>installer_item_hash</key>
        <string>aaaabbbbccccddddeeeeffff</string>
        <key>installer_item_location</key>
        <string>testpackage.dmg</string>
        <key>installer_item_size</key>
        <integer>1</integer>
        <key>minimum_os_version</key>
        <string>10.5.0</string>
        <key>name</key>
        <string>testpackage</string>
        <key>receipts</key>
        <array>
          <dict>
            <key>installed_size</key>
            <integer>1</integer>
            <key>packageid</key>
            <string>com.google.corp.testpackage</string>
            <key>version</key>
            <string>1</string>
          </dict>
        </array>
        <key>uninstall_method</key>
        <string>removepackages</string>
        <key>uninstallable</key>
        <true/>
        <key>version</key>
        <string>1</string>
      </dict>
      </plist>
      '''

    test_replacement_plist = '''<?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>autoremove</key>
        <false/>
        <key>catalogs</key>
        <array>
          <string>unstable</string>
        </array>
        <key>description</key>
        <string>test package</string>
        <key>display_name</key>
        <string>testpackage</string>
        <key>installed_size</key>
        <integer>1</integer>
        <key>installer_item_hash</key>
        <string>bbbbccccddddeeeeffffgggg</string>
        <key>installer_item_location</key>
        <string>testpackage-v2.dmg</string>
        <key>installer_item_size</key>
        <integer>1</integer>
        <key>minimum_os_version</key>
        <string>10.5.0</string>
        <key>name</key>
        <string>testpackage</string>
        <key>receipts</key>
        <array>
          <dict>
            <key>installed_size</key>
            <integer>1</integer>
            <key>packageid</key>
            <string>com.google.corp.testpackage</string>
            <key>version</key>
            <string>1</string>
          </dict>
        </array>
        <key>uninstall_method</key>
        <string>removepackages</string>
        <key>uninstallable</key>
        <true/>
        <key>version</key>
        <string>1</string>
      </dict>
      </plist>
      '''

    self.test_package = package.models.munki.PackageInfo(
        key_name='testpackage.dmg', filename='testpackage.dmg',
        catalogs=['unstable'], manifests=['unstable'],
        _plist=self.test_plist)

    self.test_proposal = package.models.munki.PackageInfoProposal(
        key_name='testpackage.dmg', catalogs=['unstable', 'testing'],
        manifests=['unstable', 'testing'], status='proposed',
        user='someone@example.com', _plist=self.test_plist,
        filename='testpackage.dmg')

    self.test_replace_proposal = package.models.munki.PackageInfoProposal(
        key_name='testpackage.dmg', catalogs=['testing'],
        manifests=['testing'], status='proposed',
        user='someone@example.com', _plist=self.test_plist,
        filename='testpackage.dmg')

    self.test_replacement_package = package.models.munki.PackageInfo(
        key_name='testpackage-v2.dmg', filename='testpackage-v2.dmg',
        catalogs=[], manifests=[],
        _plist=test_replacement_plist)

    self.test_replacement_proposal = package.models.munki.PackageInfoProposal(
        key_name='testpackage-v2.dmg', catalogs=['unstable'],
        manifests=['unstable'], status='proposed',
        user='someone@example.com', _plist=test_replacement_plist,
        filename='testpackage-v2.dmg')

    # this settings retrieved directly from datastore in models/munki.py
    settings_model.Settings.SetItem('approval_required', True)
    settings_model.Settings.SetItem('email_admin_list', 'admins@example.com')
    settings_model.Settings.SetItem('email_sender', 'server@example.com')

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(
      auth, '_GetGroupMembers', return_value=['user@example.com'])
  @mock.patch.object(
      models.PackageInfo, 'VerifyPackageIsEligibleForNewCatalogs',
      return_value=True)
  def testApproveProposal(self, *_):
    self.test_package.put()

    self.test_proposal.put()

    params = {'approve': '1'}

    self.testapp.post('/admin/package/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable', 'testing'])
    self.assertEqual(result_package.manifests, ['unstable', 'testing'])

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(
      auth, '_GetGroupMembers', return_value=['user@example.com'])
  @mock.patch.object(
      models.PackageInfo, 'VerifyPackageIsEligibleForNewCatalogs',
      return_value=True)
  def testRejectProposal(self, *_):
    self.test_package.put()

    self.test_proposal.put()

    params = {'reject': '1'}

    self.testapp.post('/admin/package/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, ['unstable'])
    self.assertEqual(result_package.proposal.manifests, ['unstable'])

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(
      models.PackageInfo, 'VerifyPackageIsEligibleForNewCatalogs',
      return_value=True)
  @mock.patch.object(auth, 'HasPermission', return_value=True)
  def testSaveToNoCatalogsOrManifests(self, *_):
    self.test_package.put()

    params = {'submit': 'save', 'catalogs': [], 'manifests': []}

    self.testapp.post('/admin/package/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, [])
    self.assertEqual(result_package.proposal.manifests, [])

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(
      models.PackageInfo, 'VerifyPackageIsEligibleForNewCatalogs',
      return_value=True)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testUnlockWithProposals(self, *_):
    self.test_package.put()

    params = {'unlock': '1'}

    self.testapp.post('/admin/package/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, [])
    self.assertEqual(result_package.proposal.manifests, [])

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(auth, 'HasPermission', return_value=True)
  def testUploadNewPlist(self, *_):
    params = {'new_pkginfo_plist': self.test_plist}

    self.testapp.post('/admin/package/', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.name, 'testpackage')

  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testReplacePackageInCatalog(self, *_):
    self.test_package.put()
    self.test_replace_proposal.put()
    self.test_replacement_package.put()
    self.test_replacement_proposal.put()

    params = {'approve': '1'}

    self.testapp.post('/admin/package/testpackage.dmg', params)
    self.testapp.post('/admin/package/testpackage-v2.dmg', params)

    result_replaced_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')
    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage-v2.dmg')

    self.assertEqual(result_replaced_package.catalogs, ['testing'])
    self.assertEqual(result_replaced_package.manifests, ['testing'])
    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])


  @mock.patch.object(auth, 'IsGroupMember', return_value=True)
  @mock.patch.object(admin.AdminHandler, 'Render')
  def testGet(self, render_mock, *_):
    package.settings.LIST_OF_CATEGORIES = 'category1,category2'

    filename = 'testpackage.dmg'
    self.test_package.put()

    resp = self.testapp.get('/admin/package/' + filename)

    self.assertEqual(httplib.OK, resp.status_int)
    args = test.GetArgFromCallHistory(render_mock, arg_index=1)

    self.assertEqual(filename, args['pkg'].filename)

  @mock.patch.object(auth, 'IsGroupMember', return_value=True)
  @mock.patch.object(package.Package, 'get', return_value=None)
  def testFilenameWithPlus(self, mock_get, *_):
    self.testapp.get(
        '/admin/package/Mercurial-4.0+169-19.dmg', status=httplib.OK)

    mock_get.assert_called_once()


if __name__ == '__main__':
  unittest.main()
