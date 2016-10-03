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
"""reports_cache module tests."""

import datetime
import logging
import random

import mox
import stubout

from google.appengine.ext import deferred
from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest
from simian.mac import models
from tests.simian.mac.common import test
from simian.mac.cron import reports_cache


class ReportsCacheModuleTest(basetest.TestCase):

  def testIsTimeDelta(self):
    """Test IsTimeDelta()."""
    dt1 = datetime.datetime(2009, 1, 1, 0, 0, 0)

    dt2 = dt1 + datetime.timedelta(seconds=10)
    self.assertTrue(
        reports_cache.IsTimeDelta(dt1, dt2, seconds=20) is not None)
    dt2 = dt1 + datetime.timedelta(seconds=30)
    self.assertFalse(
        reports_cache.IsTimeDelta(dt1, dt2, seconds=20) is not None)

    dt2 = dt1 + datetime.timedelta(minutes=10)
    self.assertTrue(
        reports_cache.IsTimeDelta(dt1, dt2, minutes=20) is not None)
    dt2 = dt1 + datetime.timedelta(minutes=30)
    self.assertFalse(
        reports_cache.IsTimeDelta(dt1, dt2, minutes=20) is not None)

    dt2 = dt1 + datetime.timedelta(hours=10)
    self.assertTrue(
        reports_cache.IsTimeDelta(dt1, dt2, hours=20) is not None)
    dt2 = dt1 + datetime.timedelta(hours=30)
    self.assertFalse(
        reports_cache.IsTimeDelta(dt1, dt2, hours=20) is not None)

    dt2 = dt1 + datetime.timedelta(days=10)
    self.assertTrue(
        reports_cache.IsTimeDelta(dt1, dt2, days=20) is not None)
    dt2 = dt1 + datetime.timedelta(days=30)
    self.assertFalse(
        reports_cache.IsTimeDelta(dt1, dt2, days=20) is not None)


class ReportsCacheCleanupTest(test.AppengineTest, mox.MoxTestBase):

  def setUp(self):
    test.AppengineTest.setUp(self)

    mox.MoxTestBase.setUp(self)

    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    test.AppengineTest.tearDown(self)

    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GenDatetimes(self, *add_seconds):
    """Generate a random datetime and additional datetimes after it.

    Args:
      *add_seconds: optional, integers supplied which will
        be added to the base random datetime.
    Returns:
      list of datetime objects, starting from a random datetime and
      including additional objects with offsets from add_seconds
    """
    d = datetime.datetime.fromtimestamp(random.randint(0, 2**31))
    output = [d]
    for add_second in add_seconds:
      output.append(d + datetime.timedelta(seconds=add_second))
    return output

  def _GenBaseSummaryOutput(self, rc):
    """Generate base summary info.

    Args:
      rc: ReportsCache instance
    Returns:
      dict, summary values initialized to 0
    """
    summary_output = {}
    for k in rc.USER_EVENTS:
      summary_output[k] = 0
    summary_output['total_events'] = 0
    summary_output['total_users'] = 0
    summary_output['total_uuids'] = 0
    return summary_output

  def _GenReportsAndSummary(self, summary_output, reports_raw):
    """Generate reports objects and calculate summary.

    Note that summary_output is modified.

    Args:
      summary_output: dict, to populate calculated summary data into
      reports_raw: list, of raw report data to feed
    Returns:
      list of objects, emulating the appearance of an Entity
      (with properties populated from reports_raw)
    """
    reports = []
    users = {}
    uuids = set()
    for report_raw in reports_raw:
      report = self.mox.CreateMockAnything()
      for k in report_raw.keys():
        setattr(report, k, report_raw[k])
      reports.append(report)

      summary_output[report_raw['event']] += 1
      summary_output['total_events'] += 1
      users.setdefault(report_raw['user'], 0)
      users[report_raw['user']] += 1
      uuids.add(report_raw['uuid'])
    summary_output['total_users'] = len(users.keys())
    summary_output['total_uuids'] = len(uuids)
    for user in users:
      summary_output.setdefault('total_users_%d_events' % users[user], 0)
      summary_output['total_users_%d_events' % users[user]] += 1
    return reports

  def testGenerateMsuUserSummaryWhenNoData(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()

    summary_output = self._GenBaseSummaryOutput(rc)

    rc._GenerateMsuUserSummary()

    summary, _ = reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True)
    self.assertEqual(summary_output, summary)

  def testGenerateMsuUserSummaryWhenData(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()

    (dt_a1, dt_a2) = self._GenDatetimes(10)
    reports_raw = [
        {
            'uuid': 'u1', 'mtime': dt_a1,
            'event': 'launched', 'user': 'a'
        },
        {
            'uuid': 'u1', 'mtime': dt_a2,
            'event': 'exit_later_clicked', 'user': 'a'
        },
    ]

    reports = []
    cursor = None
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor', 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since=None, tmp=True).AndReturn(None)

    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor('cursor%d' % (i-1)).AndReturn(None)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)

    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since=None).AndReturn(None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        'msu_user_summary_cursor', prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since=None, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary()
    self.mox.VerifyAll()

  def testGenerateMsuUserSummaryWhenDataFetchBoundary(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()

    (dt_a1, dt_a2) = self._GenDatetimes(10)
    reports_raw = [
        {
            'uuid': 'u1', 'mtime': dt_a1,
            'event': 'launched', 'user': 'a'
        },
        {
            'uuid': 'u1', 'mtime': dt_a2,
            'event': 'exit_later_clicked', 'user': 'a'
        },
        {
            'uuid': 'u2', 'mtime': dt_a1,
            'event': 'launched', 'user': 'b'
        },
        {
            'uuid': 'u2', 'mtime': dt_a2,
            'event': 'exit_later_clicked', 'user': 'b'
        },
    ]

    rc.FETCH_LIMIT = len(reports_raw)

    reports = []
    cursor = None
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    # adjust for intentional buffer boundary dropping user 'b'
    for report_raw in reports_raw:
      if report_raw['user'] == 'b':
        summary_output[report_raw['event']] -= 1
        summary_output['total_events'] -= 1
    summary_output['total_users'] -= 1
    summary_output['total_uuids'] -= 1
    summary_output['total_users_2_events'] -= 1

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor', 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since=None, tmp=True).AndReturn(None)

    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor('cursor%d' % (i-2)).AndReturn(None)  # prev cursor
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)  # stop test

    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since=None).AndReturn(None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        'msu_user_summary_cursor', prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since=None, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary()
    self.mox.VerifyAll()

  def testGenerateMsuUserSummaryWhenDataSinceOneDay(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()
    since_days = 1

    (now, dt_a1, dt_a2) = self._GenDatetimes(10, 20)
    reports_raw = [
        {
            'uuid': 'u1', 'mtime': dt_a1,
            'event': 'launched', 'user': 'a'
        },
        {
            'uuid': 'u1', 'mtime': dt_a2,
            'event': 'exit_later_clicked', 'user': 'a'
        },
    ]

    reports = []
    cursor = None
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor_%dD' % since_days, 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since='%dD' % since_days, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since='%dD' % since_days, tmp=True).AndReturn(None)

    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor('cursor%d' % (i-1)).AndReturn(None)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)

    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since='%dD' % since_days).AndReturn(None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        'msu_user_summary_cursor_%dD' % since_days, prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since='%dD' % since_days, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary(since_days=since_days, now=now)
    self.mox.VerifyAll()

  def testGenerateMsuUserSummaryWhenDataSinceOneDayTooOld(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()
    since_days = 1

    (now, dt_a1, dt_a2) = self._GenDatetimes(86500, 86550)
    reports_raw = [
        {
            'uuid': 'u1', 'mtime': dt_a1,
            'event': 'launched', 'user': 'a'
        },
        {
            'uuid': 'u1', 'mtime': dt_a2,
            'event': 'exit_later_clicked', 'user': 'a'
        },
    ]

    reports = []
    cursor = None
    cursor_name = 'msu_user_summary_cursor_%dD' % since_days
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        cursor_name, 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since='%dD' % since_days, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since='%dD' % since_days, tmp=True).AndReturn(None)

    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor('cursor%d' % (i-1)).AndReturn(None)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)

    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since='%dD' % since_days).AndReturn(None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        cursor_name, prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since='%dD' % since_days, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary(since_days=since_days, now=now)
    self.mox.VerifyAll()

  def testGenerateMsuUserSummaryWhenLotsData(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()

    reports_raw = []
    user_id = 0
    uuid_id = 0
    while len(reports_raw) < 501:
      uuid = 'uuid%d' % uuid_id
      user = 'user%d' % user_id
      (dt_a1, dt_a2) = self._GenDatetimes(10)
      reports_raw.extend([
          {
              'uuid': uuid, 'mtime': dt_a1,
              'event': 'launched', 'user': user
          },
          {
              'uuid': uuid, 'mtime': dt_a2,
              'event': 'exit_later_clicked', 'user': user
          },
      ])
      uuid_id += 1
      user_id += 1

    reports = []
    cursor = None
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor', 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since=None, tmp=True).AndReturn(None)

    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor('cursor%d' % (i-1)).AndReturn(None)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)

    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since=None).AndReturn(None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        'msu_user_summary_cursor', prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since=None, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary()
    self.mox.VerifyAll()

  def testGenerateMsuUserSummaryWhenLotsDataSlow(self):
    """Test _GenerateMsuUserSummary()."""
    rc = reports_cache.ReportsCache()

    reports_raw = []
    user_id = 0
    uuid_id = 0
    while len(reports_raw) < 501:
      uuid = 'uuid%d' % uuid_id
      user = 'user%d' % user_id
      (dt_a1, dt_a2) = self._GenDatetimes(10)
      reports_raw.extend([
          {
              'uuid': uuid, 'mtime': dt_a1,
              'event': 'launched', 'user': user
          },
          {
              'uuid': uuid, 'mtime': dt_a2,
              'event': 'exit_later_clicked', 'user': user
          },
      ])
      uuid_id += 1
      user_id += 1

    reports = []
    cursor = None
    summary = None
    summary_output = self._GenBaseSummaryOutput(rc)
    summary_empty = summary_output.copy()
    reports = self._GenReportsAndSummary(summary_output, reports_raw)

    lquery = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(reports_cache.models, 'ComputerMSULog')
    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(reports_cache.models, 'ReportsCache')

    self.mox.StubOutWithMock(reports_cache, 'time')
    self.mox.StubOutWithMock(reports_cache, 'taskqueue')

    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor', 'text_value').AndReturn(cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True).AndReturn((summary, None))
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_empty, since=None, tmp=True).AndReturn(None)

    reports_cache.time.time().AndReturn(0)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(reports)
    i = 0
    last_user = None
    for report in reports:
      if last_user != report.user:
        lquery.cursor().AndReturn('cursor%d' % i)
        i += 1
      last_user = report.user

    last_user_cursor = 'cursor%d' % (i-1)
    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    lquery.with_cursor(last_user_cursor).AndReturn(None)

    reports_cache.time.time().AndReturn(reports_cache.RUNTIME_MAX_SECS + 1)
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since=None, tmp=True).AndReturn(None)
    reports_cache.models.KeyValueCache.MemcacheWrappedSet(
        'msu_user_summary_cursor',
        'text_value', last_user_cursor).AndReturn(None)
    reports_cache.taskqueue.add(
        url='/cron/reports_cache/msu_user_summary',
        method='GET',
        countdown=5).AndReturn(None)

    # second run
    reports_cache.models.ComputerMSULog.all().AndReturn(lquery)
    reports_cache.models.KeyValueCache.MemcacheWrappedGet(
        'msu_user_summary_cursor', 'text_value').AndReturn(last_user_cursor)
    reports_cache.models.ReportsCache.GetMsuUserSummary(
        since=None, tmp=True).AndReturn([summary_output, 'mtime'])
    lquery.with_cursor(last_user_cursor)

    reports_cache.time.time().AndReturn(0)
    lquery.fetch(rc.FETCH_LIMIT).AndReturn(None)
    reports_cache.models.ReportsCache.SetMsuUserSummary(
        summary_output, since=None)
    reports_cache.models.KeyValueCache.DeleteMemcacheWrap(
        'msu_user_summary_cursor', prop_name='text_value')
    reports_cache.models.ReportsCache.DeleteMsuUserSummary(
        since=None, tmp=True).AndReturn(None)

    self.mox.ReplayAll()
    rc._GenerateMsuUserSummary()
    rc._GenerateMsuUserSummary()
    self.mox.VerifyAll()

  def testGenerateInstallCounts(self):
    """Test _GenerateInstallCounts()."""
    install_counts = {
        'foo': {
            'install_count': 2,
            'applesus': True,
            'duration_count': 1,
            'duration_total_seconds': 30,
            'duration_seconds_avg': 30},
        'bar': {'install_count': 2, 'install_fail_count': 1, 'applesus': False},
    }

    new_foo = self.mox.CreateMockAnything()
    new_foo.package = 'foo'
    new_foo.applesus = True
    new_foo.duration_seconds = 20
    new_bar = self.mox.CreateMockAnything()
    new_bar.package = 'bar'
    new_bar.applesus = False
    new_bar.duration_seconds = 10
    new_bar_success = self.mox.CreateMockAnything()
    new_bar_success.package = 'bar'
    new_bar_success.applesus = False
    new_bar_success.duration_seconds = 10
    new_bar_success2 = self.mox.CreateMockAnything()
    new_bar_success2.package = 'bar'
    new_bar_success2.applesus = False
    new_bar_success2.duration_seconds = 20
    new_zzz = self.mox.CreateMockAnything()
    new_zzz.package = 'zzz'
    new_zzz.applesus = False
    new_zzz.duration_seconds = None

    new_installs = [
        new_foo, new_bar, new_bar_success, new_zzz, new_bar_success2]

    new_install_counts = {
        'foo': {
            'install_count': 2,
            'install_fail_count': 1,
            'applesus': True,
            'duration_count': 1,
            'duration_total_seconds': 30,
            'duration_seconds_avg': 30,
         },
        'bar': {
            'install_count': 4,
            'install_fail_count': 2,
            'applesus': False,
            'duration_count': 2,
            'duration_total_seconds': 30,
            'duration_seconds_avg': 30 / 2,
         },
        'zzz': {
            'install_count': 1,
            'install_fail_count': 0,
            'applesus': False,
            'duration_count': 0,
            'duration_total_seconds': 0,
            'duration_seconds_avg': None,
        },
    }
    new_foo.IsSuccess().AndReturn(False)
    new_bar.IsSuccess().AndReturn(False)
    new_bar_success.IsSuccess().AndReturn(True)
    new_zzz.IsSuccess().AndReturn(True)
    new_bar_success2.IsSuccess().AndReturn(True)

    self.mox.StubOutWithMock(reports_cache.models, 'KeyValueCache')
    self.mox.StubOutWithMock(
        reports_cache.models.KeyValueCache, 'get_by_key_name')
    self.mox.StubOutWithMock(reports_cache.models.InstallLog, 'all')
    self.mox.StubOutWithMock(
        reports_cache.models.ReportsCache, 'GetInstallCounts')
    self.mox.StubOutWithMock(
        reports_cache.models.ReportsCache, 'SetInstallCounts')

    reports_cache.models.ReportsCache.GetInstallCounts().AndReturn(
        (install_counts, None))
    mock_query = self.mox.CreateMockAnything()
    reports_cache.models.InstallLog.all().AndReturn(mock_query)
    mock_query.order('server_datetime').AndReturn(mock_query)
    mock_cursor_obj = self.mox.CreateMockAnything()
    mock_cursor_obj.text_value = 'foocursor'
    reports_cache.models.KeyValueCache.get_by_key_name(
        'pkgs_list_cursor').AndReturn(mock_cursor_obj)
    mock_query.with_cursor(mock_cursor_obj.text_value)
    mock_query.fetch(1000).AndReturn(new_installs)

    reports_cache.models.ReportsCache.SetInstallCounts(new_install_counts)
    mock_query.cursor().AndReturn(None)
    mock_cursor_obj.put().AndReturn(None)

    self.mox.StubOutWithMock(reports_cache.deferred, 'defer')
    reports_cache.deferred.defer(
        reports_cache._GenerateInstallCounts).AndReturn(None)

    self.mox.ReplayAll()
    reports_cache._GenerateInstallCounts()
    self.mox.VerifyAll()

  def testGenerateTrendingInstallsCache(self):
    """Tests _GenerateTrendingInstallsCache."""
    package1_name = 'package1'
    package2_name = 'package2'
    package3_name = 'package3'
    package4_name = 'package4'
    expected_trending = {
        'success': {
            'packages': [
                [package1_name, 10, 66.666666666666657],
                [package4_name, 5, 33.333333333333329],
            ],
            'total': 15,
        },
        'failure': {
            'packages': [
                [package2_name, 10, 40.0],
                [package1_name, 10, 40.0],
                [package3_name, 5, 20.0],
            ],
            'total': 25,
        },
    }

    for i in range(10):
      models.InstallLog(package=package1_name, status='0').put()
      models.InstallLog(package=package1_name, status='1').put()
      models.InstallLog(package=package2_name, status='-1').put()
      if i % 2:
        models.InstallLog(package=package3_name, status='-1').put()
        models.InstallLog(package=package4_name, status='0').put()

    reports_cache._GenerateTrendingInstallsCache(1)

    taskqueue_stub = self.testbed.get_stub(testbed.TASKQUEUE_SERVICE_NAME)
    tasks = taskqueue_stub.get_filtered_tasks()
    self.assertEqual(1, len(tasks))
    deferred.run(tasks[0].payload)
    self.assertEqual(1, len(taskqueue_stub.get_filtered_tasks()))

    self.assertEqual(
        expected_trending,
        reports_cache.models.ReportsCache.GetTrendingInstalls(1)[0])

  def testGenerateComputersSummaryCache(self):
    today = datetime.datetime.utcnow()
    models.Computer(
        active=True, hostname='xyz-macbook', serial='SERIAL',
        uuid='UUID', owner='zerocool', client_version='2.3.3',
        os_version='10.10', site='MTV', track='unstable',
        config_track='unstable', connection_dates=[today],
        connections_on_corp=0, connections_off_corp=100, uptime=90000.0,
        root_disk_free=0, user_disk_free=10, preflight_datetime=today).put()

    reports_cache._GenerateComputersSummaryCache()

    taskqueue_stub = self.testbed.get_stub(testbed.TASKQUEUE_SERVICE_NAME)
    tasks = taskqueue_stub.get_filtered_tasks()
    self.assertEqual(1, len(tasks))
    deferred.run(tasks[0].payload)
    self.assertEqual(1, len(taskqueue_stub.get_filtered_tasks()))

    self.assertEqual(
        100, models.ReportsCache.GetStatsSummary()[0]['conns_off_corp'])


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
