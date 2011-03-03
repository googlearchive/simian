#!/usr/bin/env python
# 
# Copyright 2010 Google Inc. All Rights Reserved.
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
# #

"""Munki manifests module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from simian.mac.common import test
from simian.mac.munki.handlers import manifests


class HandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return manifests.Manifests()

  def GetTestClassModule(self):
    return manifests

  def testGenerateDynamicManifest(self):
    """Tests GenerateDynamicManifest()."""
    plist_xml = (
        '<plist><dict><key>catalogs</key><array><string>hello</string></array>'
        '<key>managed_installs</key><array><string>hello</string></array>'
        '</dict></plist>')
    manifest = 'stable'
    site = 'foosite'
    os_version = '10.6.5'
    client_id = {'track': manifest, 'site': site, 'os_version': os_version}

    install_type_one = 'optional_installs'
    site_mod_one = self.mox.CreateMockAnything()
    site_mod_one.manifests = [manifest]
    site_mod_one.enabled = True
    site_mod_one.install_type = install_type_one
    site_mod_one.value = 'foo pkg 1'

    install_type_two = 'managed_installs'
    site_mod_two = self.mox.CreateMockAnything()
    site_mod_two.manifests = [manifest]
    site_mod_two.enabled = True
    site_mod_two.install_type = install_type_two
    site_mod_two.value = 'foo pkg 2'
    site_mod_disabled = self.mox.CreateMockAnything()
    site_mod_disabled.enabled = False
    site_mods = [site_mod_one, site_mod_two, site_mod_disabled]
    mock_query = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(manifests.models.SiteManifestModification, 'all')
    manifests.models.SiteManifestModification.all().AndReturn(mock_query)
    mock_query.filter('site =', site).AndReturn(site_mods)

    os_version_mod_one = self.mox.CreateMockAnything()
    os_version_mod_one.manifests = [manifest]
    os_version_mod_one.enabled = True
    os_version_mod_one.install_type = 'managed_installs'
    os_version_mod_one.value = 'foo os version pkg'
    os_version_mods = [os_version_mod_one]
    mock_query = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(
        manifests.models.OSVersionManifestModification, 'all')
    manifests.models.OSVersionManifestModification.all().AndReturn(mock_query)
    mock_query.filter('os_version =', os_version).AndReturn(os_version_mods)

    # Setup dict of expected output xml.
    tmp_plist_exp = manifests.plist_module.MunkiManifestPlist(plist_xml)
    tmp_plist_exp.Parse()
    expected_out_dict = tmp_plist_exp.GetContents()
    expected_out_dict[install_type_one] = [site_mod_one.value]
    expected_out_dict[install_type_two].append(site_mod_two.value)
    expected_out_dict[install_type_two].append(os_version_mod_one.value)

    self.mox.ReplayAll()
    # Generate the dynamic manifest, then get dict output to compare to the
    # expected output.
    out_xml = manifests.common.GenerateDynamicManifest(plist_xml, client_id)
    tmp_plist_out = manifests.plist_module.MunkiManifestPlist(out_xml)
    tmp_plist_out.Parse()
    out_dict = tmp_plist_out.GetContents()
    self.assertEqual(out_dict, expected_out_dict)
    self.mox.VerifyAll()


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()