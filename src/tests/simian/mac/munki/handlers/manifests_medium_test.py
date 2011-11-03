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
        '<key>managed_updates</key><array><string>hello</string></array>'
        '</dict></plist>')
    manifest = 'stable'
    site = 'foosite'
    os_version = '10.6.5'
    owner = 'foouser'
    uuid = '12345-abcdef'
    client_id = {
        'track': manifest, 'site': site, 'os_version': os_version,
        'owner': owner, 'uuid': uuid,
    }

    install_type_optional_installs = 'optional_installs'
    install_type_managed_updates = 'managed_updates'

    site_mod_one = self.mox.CreateMockAnything()
    site_mod_one.manifests = [manifest]
    site_mod_one.enabled = True
    site_mod_one.install_types = [install_type_optional_installs]
    site_mod_one.value = 'foo pkg 1'

    site_mod_two = self.mox.CreateMockAnything()
    site_mod_two.manifests = [manifest]
    site_mod_two.enabled = True
    site_mod_two.install_types = [install_type_managed_updates]
    site_mod_two.value = 'foo pkg 2'
    site_mod_disabled = self.mox.CreateMockAnything()
    site_mod_disabled.enabled = False
    site_mods = [site_mod_one, site_mod_two, site_mod_disabled]
    self.mox.StubOutWithMock(
        manifests.models.SiteManifestModification,
        'MemcacheWrappedGetAllFilter')
    manifests.models.SiteManifestModification.MemcacheWrappedGetAllFilter(
        (('site =', site),)).AndReturn(site_mods)

    os_version_mod_one = self.mox.CreateMockAnything()
    os_version_mod_one.manifests = [manifest]
    os_version_mod_one.enabled = True
    os_version_mod_one.install_types = [install_type_managed_updates]
    os_version_mod_one.value = 'foo os version pkg'
    os_version_mods = [os_version_mod_one]
    self.mox.StubOutWithMock(
        manifests.models.OSVersionManifestModification,
        'MemcacheWrappedGetAllFilter')
    manifests.models.OSVersionManifestModification.MemcacheWrappedGetAllFilter(
        (('os_version =', os_version),)).AndReturn(os_version_mods)

    owner_mod_one = self.mox.CreateMockAnything()
    owner_mod_one.manifests = [manifest]
    owner_mod_one.enabled = True
    owner_mod_one.install_types = [
        install_type_optional_installs, install_type_managed_updates]
    owner_mod_one.value = 'foo owner pkg'
    owner_mods = [owner_mod_one]
    self.mox.StubOutWithMock(
        manifests.models.OwnerManifestModification,
        'MemcacheWrappedPropMapGetAll')
    manifests.models.OwnerManifestModification.MemcacheWrappedPropMapGetAll(
        'owner', owner).AndReturn(owner_mods)

    uuid_mod_one = self.mox.CreateMockAnything()
    uuid_mod_one.manifests = [manifest]
    uuid_mod_one.enabled = True
    uuid_mod_one.install_types = [install_type_managed_updates]
    uuid_mod_one.value = 'foo uuid pkg'
    uuid_mods = [uuid_mod_one]
    self.mox.StubOutWithMock(
        manifests.models.UuidManifestModification,
        'MemcacheWrappedPropMapGetAll')
    manifests.models.UuidManifestModification.MemcacheWrappedPropMapGetAll(
        'uuid', uuid).AndReturn(uuid_mods)

    # Setup dict of expected output xml.
    tmp_plist_exp = manifests.plist_module.MunkiManifestPlist(plist_xml)
    tmp_plist_exp.Parse()
    expected_out_dict = tmp_plist_exp.GetContents()
    expected_out_dict[install_type_optional_installs] = [site_mod_one.value]
    expected_out_dict[install_type_managed_updates].append(site_mod_two.value)
    expected_out_dict[install_type_managed_updates].append(
        os_version_mod_one.value)
    expected_out_dict[install_type_optional_installs].append(
        owner_mod_one.value)
    expected_out_dict[install_type_managed_updates].append(owner_mod_one.value)
    expected_out_dict[install_type_managed_updates].append(uuid_mod_one.value)

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