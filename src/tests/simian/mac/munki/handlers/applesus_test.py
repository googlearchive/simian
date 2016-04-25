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
import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import applesus


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
    self.MockDoAnyAuth(and_return=session)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)

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
    self.MockDoAnyAuth(and_return=session)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)

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
    self.MockDoAnyAuth(and_return=session)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str='').AndReturn(client_id)

    self.MockModelStaticBase(
        'AppleSUSCatalog', 'MemcacheWrappedGet', catalog_name).AndReturn(None)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testGet404WhenArgSupplied(self):
    """Tests AppleSUS.get() where track is not found."""
    track = 'notfound'
    full_os_version = '10.6.6'
    major_minor_os_version = '10.6'
    client_id_str = 'track=%s|os_version=%s' % (track, full_os_version)
    client_id = {'track': track, 'os_version': full_os_version}
    session = None  # easier than mock obj, no .uuid property
    catalog_name = '%s_%s' % (major_minor_os_version, track)

    self.mox.StubOutWithMock(applesus.handlers, 'GetClientIdForRequest')
    self.MockDoAnyAuth(and_return=session)
    applesus.handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str=client_id_str).AndReturn(
            client_id)

    self.MockModelStaticBase(
        'AppleSUSCatalog', 'MemcacheWrappedGet', catalog_name).AndReturn(None)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(client_id_str)
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
