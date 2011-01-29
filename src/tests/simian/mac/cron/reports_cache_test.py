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

"""reports_cache module tests."""



import datetime
import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.cron import reports_cache


class ReportsCacheModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class ReportsCacheCleanupTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(reports_cache.models.Computer, 'AllActive')
    self.mox.StubOutWithMock(
        reports_cache.models.ReportsCache, 'SetClientCount')

    tracks = {'stable': 1000, 'unstable': 20, 'testing': 100}
    total_count = sum(tracks.values())
    reports_cache.common.TRACKS = tracks

    for track, count in tracks.iteritems():
      mock_query = self.mox.CreateMockAnything()
      reports_cache.models.Computer.AllActive(
          keys_only=True).AndReturn(mock_query)
      mock_query.filter('track =', track).AndReturn(mock_query)
      mock_query.count().AndReturn(count)
      reports_cache.models.ReportsCache.SetClientCount(
          count, 'track', track).AndReturn(None)
    reports_cache.models.ReportsCache.SetClientCount(total_count).AndReturn(
        None)

    now = datetime.datetime.utcnow()
    self.mox.StubOutWithMock(datetime, 'datetime')
    reports_cache.datetime.datetime.utcnow().AndReturn(now)
    days_active = {1: 100, 7: 400, 30: 1000}
    reports_cache.DAYS_ACTIVE = days_active
    for days, count in days_active.iteritems():
      days_datetime = now - datetime.timedelta(days=days)
      mock_query = self.mox.CreateMockAnything()
      reports_cache.models.Computer.AllActive(
          keys_only=True).AndReturn(mock_query)
      mock_query.filter('preflight_datetime >', days_datetime).AndReturn(
          mock_query)
      mock_query.count().AndReturn(count)
      reports_cache.models.ReportsCache.SetClientCount(
          count, 'days_active', days).AndReturn(None)

    rc = reports_cache.ReportsCache()

    self.mox.ReplayAll()
    rc.get('client_counts')
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()