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
"""Munki handlers __init__ module tests."""

import datetime
import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki import handlers


class HandlersTest(test.RequestHandlerTest):
  """__init__.py handlers tests."""

  def GetTestClassInstance(self):
    return handlers

  def GetTestClassModule(self):
    return handlers

  def testStrHeaderDateToDatetime(self):
    """Tests StrHeaderDateToDatetime()."""
    header_dt_str = 'Wed, 06 Oct 2010 03:23:34 GMT'
    dt = datetime.datetime(2010, 10, 06, 03, 23, 34)  # same date
    r = handlers.StrHeaderDateToDatetime(header_dt_str)
    self.assertEqual(dt, r)

  def testStrHeaderDateToDatetimeNone(self):
    """Tests StrHeaderDateToDatetime()."""
    self.assertEqual(None, handlers.StrHeaderDateToDatetime(''))

  def testIsClientResourceExpiredWithEmptyDate(self):
    """Tests IsClientResourceExpired() with empty header str date."""
    self.assertTrue(handlers.IsClientResourceExpired(None, ''))

  def testPackageModifiedWithInvalidDate(self):
    """Tests IsClientResourceExpired() with non-parsable header str date."""
    self.assertTrue(
        handlers.IsClientResourceExpired(None, 'date will not parse'))

  def testPackageModifiedMatchingDate(self):
    """Tests IsClientResourceExpired() with matching header str date."""
    header_dt_str = 'Wed, 06 Oct 2010 03:23:34 GMT'
    dt = datetime.datetime(2010, 10, 06, 03, 23, 34)  # same date
    self.assertFalse(handlers.IsClientResourceExpired(dt, header_dt_str))

  def testPackageModifiedWherePackageDateNewer(self):
    """Tests IsClientResourceExpired() with matching header str date."""
    header_dt_str = 'Mon, 01 Jan 1930 01:00:00 GMT'
    dt = datetime.datetime(2010, 10, 06, 03, 23, 34)  # later date
    self.assertTrue(handlers.IsClientResourceExpired(dt, header_dt_str))

  def testGetClientIdForRequestWithSession(self):
    """Tests GetClientIdForRequest()."""
    track = 'stable'
    os_version = '10.6.6'
    client_id = 'client_id'
    client_id_dict = {'track': track, 'os_version': os_version}
    session = self.mox.CreateMockAnything()
    session.uuid = 'uuid'
    request = self.mox.CreateMockAnything()
    request.headers = self.mox.CreateMockAnything()

    request.headers.get('X-munki-client-id', '').AndReturn(client_id)
    self.mox.StubOutWithMock(handlers.common, 'ParseClientId')
    handlers.common.ParseClientId(client_id, uuid=session.uuid).AndReturn(
        client_id_dict)

    self.mox.ReplayAll()
    r = handlers.GetClientIdForRequest(
        request, session=session, client_id_str='')
    self.assertEqual(r, client_id_dict)
    self.mox.VerifyAll()

  def testGetClientIdForRequestWithoutSession(self):
    """Tests GetClientIdForRequest()."""
    track = 'stable'
    os_version = '10.6.6'
    client_id_dict = {'track': track, 'os_version': os_version}
    client_id_str = 'track=%s|os_version=%s' % (track, os_version)
    client_id_str_quoted = handlers.urllib.quote(client_id_str)
    request = self.mox.CreateMockAnything()
    request.headers = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(handlers.common, 'ParseClientId')
    handlers.common.ParseClientId(client_id_str).AndReturn(client_id_dict)

    self.mox.ReplayAll()
    r = handlers.GetClientIdForRequest(
        request, session=None, client_id_str=client_id_str_quoted)
    self.assertEqual(r, client_id_dict)
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
