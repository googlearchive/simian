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
"""Munki applesus module tests."""

import datetime
import httplib
import logging


import mock
import stubout
import webtest

from google.apputils import app
from simian.auth import gaeserver
from simian.mac import models
from tests.simian.mac.common import test
from simian.mac.munki.handlers import applesus
from simian.mac.urls import app as gae_app


class AppleSUSCatalogsHandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return applesus.AppleSUS()

  def GetTestClassModule(self):
    return applesus

  def testGetSuccess(self):
    """Tests AppleSUS.get()."""
    track = 'stable'
    full_os_version = '10.6.6'
    major_minor_os_version = '10.6'
    client_id = {'track': track, 'os_version': full_os_version}
    session = 'session'
    catalog_date = datetime.datetime(2011, 01, 01)
    header_date_str = 'foo str date'
    catalog_name = '%s_%s' % (major_minor_os_version, track)

    self.mox.StubOutWithMock(applesus.handlers, 'GetClientIdForRequest')
    self.MockDoMunkiAuth(
        and_return=session, require_level=gaeserver.LEVEL_APPLESUS)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session).AndReturn(client_id)

    catalog = self.MockModelStatic(
        'AppleSUSCatalog', 'MemcacheWrappedGet', catalog_name)
    catalog.mtime = catalog_date
    self.request.headers.get('If-Modified-Since', '').AndReturn(
        header_date_str)
    self.mox.StubOutWithMock(applesus.handlers, 'IsClientResourceExpired')
    applesus.handlers.IsClientResourceExpired(
        catalog_date, header_date_str).AndReturn(True)
    self.response.headers['Last-Modified'] = catalog_date.strftime(
        applesus.handlers.HEADER_DATE_FORMAT)
    catalog.plist = 'fooplist'
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(catalog.plist).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGetSuccessWhereCatalogNotChanged(self):
    """Tests AppleSUS.get()."""
    track = 'stable'
    full_os_version = '10.6.6'
    major_minor_os_version = '10.6'
    client_id = {'track': track, 'os_version': full_os_version}
    session = 'session'
    catalog_date = datetime.datetime(2011, 01, 01)
    header_date_str = 'foo str date'
    catalog_name = '%s_%s' % (major_minor_os_version, track)

    self.mox.StubOutWithMock(applesus.handlers, 'GetClientIdForRequest')
    self.MockDoMunkiAuth(
        and_return=session, require_level=gaeserver.LEVEL_APPLESUS)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session).AndReturn(client_id)

    catalog = self.MockModelStatic(
        'AppleSUSCatalog', 'MemcacheWrappedGet', catalog_name)
    catalog.mtime = catalog_date
    self.request.headers.get('If-Modified-Since', '').AndReturn(
        header_date_str)
    self.mox.StubOutWithMock(applesus.handlers, 'IsClientResourceExpired')
    applesus.handlers.IsClientResourceExpired(
        catalog_date, header_date_str).AndReturn(False)
    self.response.set_status(304)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGet404(self):
    """Tests AppleSUS.get() where track is not found."""
    track = 'notfound'
    client_id = {'track': track, 'os_version': ''}
    session = 'session'
    catalog_name = '_%s' % track

    self.mox.StubOutWithMock(applesus.handlers, 'GetClientIdForRequest')
    self.MockDoMunkiAuth(
        and_return=session, require_level=gaeserver.LEVEL_APPLESUS)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session).AndReturn(client_id)

    self.MockModelStaticBase(
        'AppleSUSCatalog', 'MemcacheWrappedGet', catalog_name).AndReturn(None)
    self.response.set_status(httplib.NOT_FOUND).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testSupplyClientIdAndTokenInUrl(self):
    testapp = webtest.TestApp(gae_app)

    plist = 'PLIST'
    models.AppleSUSCatalog(key_name='10.11_stable', plist=plist).put()

    headers = {
        applesus.MUNKI_CLIENT_ID_HEADER_KEY: 'track=stable|os_version=10.11'}

    ss = models.AuthSession(uuid='34')
    with mock.patch.object(gaeserver, 'DoMunkiAuth', return_value=ss):
      resp = testapp.post(
          '/applesus/', status=httplib.OK,
          headers=headers)
    resp = testapp.get('/applesus/%s' % resp.body, status=httplib.OK)
    self.assertEqual(plist, resp.body)

  def testMultipleRequestsReturnSameToken(self):
    # We don't want change CatalogURL too often.
    testapp = webtest.TestApp(gae_app)

    headers = {
        applesus.MUNKI_CLIENT_ID_HEADER_KEY: 'track=stable|os_version=10.11'}

    ss = models.AuthSession(uuid='34')
    with mock.patch.object(gaeserver, 'DoMunkiAuth', return_value=ss):
      token1 = testapp.post(
          '/applesus/', status=httplib.OK,
          headers=headers).body
      token2 = testapp.post(
          '/applesus/', status=httplib.OK,
          headers=headers).body
    self.assertEqual(token1, token2)

  def testEncodeMsg(self):
    msg = {'a': 1, 'b': 2}
    self.assertEqual(
        msg, applesus._DecodeMsg(applesus._EncodeMsg(msg)))


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
