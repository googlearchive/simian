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

  def testGetSuccessNonStable(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=testing|foo=withpipe'
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(
        client_id_quoted)
    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    manifests.common.ParseClientId(client_id, uuid=uuid).AndReturn(
        client_id_dict)
    self.mox.StubOutWithMock(manifests.common, 'IsPanicModeNoPackages')
    manifests.common.IsPanicModeNoPackages().AndReturn(False)
    manifest = self.MockModelStatic('Manifest', 'MemcacheWrappedGet', track)
    manifest.plist = 'fooplist'
    self.mox.StubOutWithMock(manifests, 'GenerateDynamicManifest')
    manifests.GenerateDynamicManifest(manifest.plist, client_id_dict).AndReturn(
        manifest.plist)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(manifest.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessNonStableClientIdInUrl(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=testing|foo=withpipe'
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    self.MockDoAnyAuth()
    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    manifests.common.ParseClientId(client_id).AndReturn(client_id_dict)
    self.mox.StubOutWithMock(manifests.common, 'IsPanicModeNoPackages')
    manifests.common.IsPanicModeNoPackages().AndReturn(False)
    manifest = self.MockModelStatic('Manifest', 'MemcacheWrappedGet', track)
    self.mox.StubOutWithMock(manifests, 'GenerateDynamicManifest')
    manifest.plist = 'fooplist'
    manifests.GenerateDynamicManifest(manifest.plist, client_id_dict).AndReturn(
        manifest.plist)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(manifest.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(client_id_quoted)
    self.mox.VerifyAll()

  def testGet404(self):
    """Tests Manifests.get() where name is not found."""
    track = 'notvalid'
    client_id = 'track=%s' % track
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(client_id)
    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    manifests.common.ParseClientId(client_id, uuid=uuid).AndReturn(
        client_id_dict)
    self.mox.StubOutWithMock(manifests.common, 'IsPanicModeNoPackages')
    manifests.common.IsPanicModeNoPackages().AndReturn(False)
    self.MockModelStaticBase(
        'Manifest', 'MemcacheWrappedGet', track).AndReturn(None)
    self.response.set_status(404)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetDisabled(self):
    """Tests Manifests.get() where manifest is disabled."""
    track = 'disabled'
    client_id = 'track=%s' % track
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(client_id)
    mock_model = self.mox.CreateMockAnything()
    mock_model.enabled = False
    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    manifests.common.ParseClientId(client_id, uuid=uuid).AndReturn(
        client_id_dict)
    self.mox.StubOutWithMock(manifests.common, 'IsPanicModeNoPackages')
    manifests.common.IsPanicModeNoPackages().AndReturn(False)
    self.MockModelStaticBase(
        'Manifest', 'MemcacheWrappedGet', track).AndReturn(mock_model)
    self.response.set_status(503)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetPanicModeNoPackages(self):
    """Tests Manifests.get() where manifest is in panic mode."""
    track = 'disabled'
    client_id = 'track=%s' % track
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(client_id)
    mock_model = self.mox.CreateMockAnything()
    mock_model.enabled = False
    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    manifests.common.ParseClientId(client_id, uuid=uuid).AndReturn(
        client_id_dict)
    self.mox.StubOutWithMock(manifests.common, 'IsPanicModeNoPackages')
    manifests.common.IsPanicModeNoPackages().AndReturn(True)
    plist_xml = '%s%s' % (
        manifests.plist_module.PLIST_HEAD,
        manifests.plist_module.PLIST_FOOT)
    self.response.out.write(plist_xml).AndReturn(True)
    self.response.headers.__setitem__(
        'Content-Type',
        'text/xml; charset=utf-8').AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testModifyList(self):
    """Tests _ModifyList()."""
    l = []
    manifests._ModifyList(l, 'yes')
    manifests._ModifyList(l, 'no')
    self.assertEqual(l, ['yes', 'no'])  # test modify add.

    manifests._ModifyList(l, '-no')
    self.assertEqual(l, ['yes'])  # test modify remove.

    manifests._ModifyList(l, '-This value does not exist')
    self.assertEqual(l, ['yes'])  # test modify remove of non-existent value.

  def testGenerateDynamicManifest(self):
    """Tests GenerateDynamicManifest()."""
    plist_xml = 'fooxml'
    manifest = 'stable'
    site = 'foosite'
    os_version = '10.6.5'
    client_id = {'track': manifest, 'site': site, 'os_version': os_version}

    install_type_one = 'optional_installs'
    value_one = 'foopkg'
    site_mod_one = self.mox.CreateMockAnything()
    site_mod_one.manifests = [manifest]
    site_mod_one.enabled = True
    site_mod_one.install_type = install_type_one
    site_mod_one.value = value_one
    site_mod_disabled = self.mox.CreateMockAnything()
    site_mod_disabled.enabled = False
    site_mods = [site_mod_one, site_mod_disabled]
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

    mock_plist = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(manifests.plist_module, 'UpdateIterable')
    self.mox.StubOutWithMock(manifests.plist_module, 'MunkiManifestPlist')
    manifests.plist_module.MunkiManifestPlist(plist_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)

    manifests.plist_module.UpdateIterable(
        mock_plist, site_mod_one.install_type, site_mod_one.value, default=[],
        op=manifests._ModifyList)

    manifests.plist_module.UpdateIterable(
        mock_plist, os_version_mod_one.install_type,
        os_version_mod_one.value, default=[], op=manifests._ModifyList)

    mock_plist.GetXml().AndReturn(plist_xml)

    self.mox.ReplayAll()
    self.assertEqual(
        plist_xml, manifests.GenerateDynamicManifest(plist_xml, client_id))
    self.mox.VerifyAll()


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()