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
import unittest
import mock
import stubout

import webapp2
import webtest

from simian.mac import models
from simian.mac.admin import package
from tests.simian.mac.common import test
from simian.mac.models import munki
from simian.mac.models import settings


class PackageInfoProposalTest(test.AppengineTest):
  """Test PackageInfoProposal class."""

  def setUp(self):
    super(PackageInfoProposalTest, self).setUp()

    app = webapp2.WSGIApplication([('/(.*)', package.Package)])
    self.testapp = webtest.TestApp(app)

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

    package.settings.APPROVAL_REQUIRED = True
    package.settings.EMAIL_ON_EVERY_CHANGE = False
    settings.Settings.SetItem('approval_required', True)
    settings.Settings.SetItem('email_admin_list', 'admins@example.com')
    settings.Settings.SetItem('email_sender', 'server@example.com')

    munki.Catalog.Generate = mock.Mock(return_value=True)
    munki.Manifest.Generate = mock.Mock(return_value=True)

  def testProposeToCatalogsAndManifests(self):
    self.test_package.put()

    package.auth.HasPermission = lambda x: True
    package.xsrf.XsrfTokenValidate = lambda x, y: True
    package.models.PackageInfo.VerifyPackageIsEligibleForNewCatalogs = (
        lambda x, y: True)

    params = {'submit': 'save', 'catalogs': ['unstable', 'testing'],
              'manifests': ['unstable', 'testing']}

    self.testapp.post('/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, ['unstable', 'testing'])
    self.assertEqual(result_package.proposal.manifests, ['unstable', 'testing'])

  def testApproveProposal(self):
    self.test_package.put()

    package.auth._GetGroupMembers = lambda x: ['user@example.com']
    package.xsrf.XsrfTokenValidate = lambda x, y: True
    package.models.PackageInfo.VerifyPackageIsEligibleForNewCatalogs = (
        lambda x, y: True)

    self.test_proposal.put()

    params = {'approve': '1'}

    self.testapp.post('/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable', 'testing'])
    self.assertEqual(result_package.manifests, ['unstable', 'testing'])

  def testRejectProposal(self):
    self.test_package.put()

    package.auth._GetGroupMembers = lambda x: ['user@example.com']
    package.xsrf.XsrfTokenValidate = lambda x, y: True
    package.models.PackageInfo.VerifyPackageIsEligibleForNewCatalogs = (
        lambda x, y: True)

    self.test_proposal.put()

    params = {'reject': '1'}

    self.testapp.post('/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, ['unstable'])
    self.assertEqual(result_package.proposal.manifests, ['unstable'])

  def testSaveToNoCatalogsOrManifests(self):
    self.test_package.put()

    package.auth.HasPermission = lambda x: True
    package.xsrf.XsrfTokenValidate = lambda x, y: True
    package.models.PackageInfo.VerifyPackageIsEligibleForNewCatalogs = (
        lambda x, y: True)

    params = {'submit': 'save', 'catalogs': [], 'manifests': []}

    self.testapp.post('/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, [])
    self.assertEqual(result_package.proposal.manifests, [])

  def testUnlockWithProposals(self):
    self.test_package.put()

    package.auth.HasPermission = lambda x: True
    package.xsrf.XsrfTokenValidate = lambda x, y: True
    package.models.PackageInfo.VerifyPackageIsEligibleForNewCatalogs = (
        lambda x, y: True)

    params = {'unlock': '1'}

    self.testapp.post('/testpackage.dmg', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])
    self.assertEqual(result_package.proposal.catalogs, [])
    self.assertEqual(result_package.proposal.manifests, [])

  def testUploadNewPlist(self):
    package.auth.HasPermission = lambda x: True
    package.xsrf.XsrfTokenValidate = lambda x, y: True

    params = {'new_pkginfo_plist': self.test_plist}

    self.testapp.post('/', params)

    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')

    self.assertEqual(result_package.name, 'testpackage')

  def testReplacePackageInCatalog(self):
    self.test_package.put()
    self.test_replace_proposal.put()
    self.test_replacement_package.put()
    self.test_replacement_proposal.put()

    package.auth.HasPermission = lambda x: True
    package.xsrf.XsrfTokenValidate = lambda x, y: True

    params = {'approve': '1'}

    self.testapp.post('/testpackage.dmg', params)
    self.testapp.post('/testpackage-v2.dmg', params)

    result_replaced_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage.dmg')
    result_package = package.models.munki.PackageInfo.get_by_key_name(
        'testpackage-v2.dmg')

    self.assertEqual(result_replaced_package.catalogs, ['testing'])
    self.assertEqual(result_replaced_package.manifests, ['testing'])
    self.assertEqual(result_package.catalogs, ['unstable'])
    self.assertEqual(result_package.manifests, ['unstable'])

  def testNotifyAdminsOfPackageChangeFromPlist(self):
    self.test_package.put()

    pkginfo = models.PackageInfo.get_by_key_name(self.test_package.filename)
    pkginfo._is_approval_required = False
    pkginfo.MakeSafeToModify()

    pkginfo, log = models.PackageInfo.UpdateFromPlist(
        self.test_plist, create_new=False)

    request = None
    response = mock.MagicMock()
    p = package.Package(request, response)
    p.NotifyAdminsOfPackageChangeFromPlist(log, defer=False)

    mail_stub = self.testbed.get_stub('mail')
    messages = mail_stub.get_sent_messages()

    self.assertEqual(1, len(messages))

    body = messages[0].body.payload.split('\n')
    inserted = [line for line in body if line[0] == '+']
    deleted = [line for line in body if line[0] == '-']
    not_changed = [line for line in body if line[0] == ' ']

    self.assertEqual(1, len(inserted))
    self.assertEqual(4, len(deleted))
    self.assertEqual(44, len(not_changed))
    self.assertEqual('+       <string>unstable</string>', inserted[0])


if __name__ == '__main__':
  unittest.main()
