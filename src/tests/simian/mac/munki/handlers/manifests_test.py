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

  def testGetSuccessWhenSessionUuid(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=%s|foo=withpipe' % track
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    plist_xml = 'manifest xml'

    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(
        client_id_quoted)
    manifests.common.ParseClientId(
        client_id, uuid=mock_session.uuid).AndReturn(client_id_dict)
    manifests.common.GetComputerManifest(
        client_id=client_id_dict, packagemap=False).AndReturn(plist_xml)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhenSessionNoUuid(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=%s|foo=withpipe' % track
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    plist_xml = 'manifest xml'

    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return='has no uuid')
    manifests.common.ParseClientId(client_id).AndReturn(client_id_dict)
    manifests.common.GetComputerManifest(
        client_id=client_id_dict, packagemap=False).AndReturn(plist_xml)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(client_id)
    self.mox.VerifyAll()

  def testGetSuccessWhenManifestNotFoundError(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=%s|foo=withpipe' % track
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    plist_xml = 'manifest xml'

    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(
        client_id_quoted)
    manifests.common.ParseClientId(
        client_id, uuid=mock_session.uuid).AndReturn(client_id_dict)
    manifests.common.GetComputerManifest(
        client_id=client_id_dict, packagemap=False).AndRaise(
            manifests.common.ManifestNotFoundError)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhenManifestDisabledError(self):
    """Tests Manifests.get()."""
    track = 'testing'
    client_id = 'track=%s|foo=withpipe' % track
    client_id_quoted = manifests.urllib.quote(client_id)
    client_id_dict = {'track': track}
    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    plist_xml = 'manifest xml'

    self.mox.StubOutWithMock(manifests.common, 'ParseClientId')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=mock_session)
    self.request.headers.get('X-munki-client-id', '').AndReturn(
        client_id_quoted)
    manifests.common.ParseClientId(
        client_id, uuid=mock_session.uuid).AndReturn(client_id_dict)
    manifests.common.GetComputerManifest(
        client_id=client_id_dict, packagemap=False).AndRaise(
            manifests.common.ManifestDisabledError)
    self.response.set_status(503).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def ZtestGetSuccessNonStable(self):
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
    self.mox.StubOutWithMock(manifests.common, 'GenerateDynamicManifest')
    manifests.common.GenerateDynamicManifest(
        manifest.plist, client_id_dict).AndReturn(manifest.plist)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(manifest.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def ZtestGetSuccessNonStableClientIdInUrl(self):
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
    self.mox.StubOutWithMock(manifests.common, 'GenerateDynamicManifest')
    manifest.plist = 'fooplist'
    manifests.common.GenerateDynamicManifest(
        manifest.plist, client_id_dict).AndReturn(manifest.plist)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(manifest.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(client_id_quoted)
    self.mox.VerifyAll()

  def ZtestGet404(self):
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

  def ZtestGetDisabled(self):
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

  def ZtestGetPanicModeNoPackages(self):
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



def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()