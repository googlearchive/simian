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
"""Munki manifests module tests."""

import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import manifests


class HandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return manifests.Manifests()

  def GetTestClassModule(self):
    return manifests

  def testGetSuccess(self):
    """Tests Manifests.get()."""
    client_id = {'track': 'track'}
    session = 'session'
    plist_xml = 'manifest xml'

    self.mox.StubOutWithMock(manifests.handlers, 'GetClientIdForRequest')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=session)
    manifests.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)
    manifests.common.GetComputerManifest(
        client_id=client_id, packagemap=False).AndReturn(plist_xml)
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhenManifestNotFoundError(self):
    """Tests Manifests.get()."""
    client_id = {'track': 'track'}
    session = 'session'

    self.mox.StubOutWithMock(manifests.handlers, 'GetClientIdForRequest')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=session)
    manifests.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)
    manifests.common.GetComputerManifest(
        client_id=client_id, packagemap=False).AndRaise(
            manifests.common.ManifestNotFoundError)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhenManifestDisabledError(self):
    """Tests Manifests.get()."""
    client_id = {'track': 'track'}
    session = 'session'

    self.mox.StubOutWithMock(manifests.handlers, 'GetClientIdForRequest')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=session)
    manifests.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)
    manifests.common.GetComputerManifest(
        client_id=client_id, packagemap=False).AndRaise(
            manifests.common.ManifestDisabledError)
    self.response.set_status(503).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhenOtherManifestError(self):
    """Tests Manifests.get()."""
    client_id = {'track': 'track'}
    session = 'session'

    self.mox.StubOutWithMock(manifests.handlers, 'GetClientIdForRequest')
    self.mox.StubOutWithMock(manifests.common, 'GetComputerManifest')

    self.MockDoAnyAuth(and_return=session)
    manifests.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)
    manifests.common.GetComputerManifest(
        client_id=client_id, packagemap=False).AndRaise(
            manifests.common.Error)
    self.response.set_status(503).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
