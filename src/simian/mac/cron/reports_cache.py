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
"""Module containing url handler for report calculation.

Classes:
  ReportsCache: the url handler
"""

import datetime
import httplib
import logging
import time
import webapp2

from google.appengine.api import taskqueue
from google.appengine.ext import db
from google.appengine.ext import deferred

from simian.mac.common import datastore_locks
from simian.mac import models
from simian.mac.admin import summary as summary_module


TRENDING_INSTALLS_LIMIT = 5
RUNTIME_MAX_SECS = 30


class ReportsCache(webapp2.RequestHandler):
  """Class to cache reports on a regular basis."""

  USER_EVENTS = [
      'launched',
      'install_with_logout',
      'install_without_logout',
      'cancelled',
      'exit_later_clicked',
      'exit_installwithnologout',
      'conflicting_apps'
  ]

  FETCH_LIMIT = 500

  def get(self, name=None, arg=None):
    """Handle GET."""

    if name == 'summary':
      _GenerateComputersSummaryCache()
    elif name == 'installcounts':
      _GenerateInstallCounts()
    elif name == 'trendinginstalls':
      if arg:
        try:
          kwargs = {'since_hours': int(arg)}
        except ValueError:
          kwargs = {}
      else:
        kwargs = {}
      _GenerateTrendingInstallsCache(**kwargs)
    elif name == 'pendingcounts':
      self._GeneratePendingCounts()
    elif name == 'msu_user_summary':
      if arg:
        try:
          kwargs = {'since_days': int(arg)}
        except ValueError:
          kwargs = {}
      else:
        kwargs = {}
      self._GenerateMsuUserSummary(**kwargs)
    else:
      logging.warning('Unknown ReportsCache cron requested: %s', name)
      self.response.set_status(httplib.NOT_FOUND)

  def _GenerateMsuUserSummary(self, since_days=None, now=None):
    """Generate summary of MSU user data.

    Args:
      since_days: int, optional, only report on the last x days
      now: datetime.datetime, optional, supply an alternative
        value for the current date/time
    """
    lock_name = 'msu_user_summary_lock'
    cursor_name = 'msu_user_summary_cursor'
    if since_days is None:
      since = None
    else:
      since = '%dD' % since_days
      lock_name = '%s_%s' % (lock_name, since)
      cursor_name = '%s_%s' % (cursor_name, since)

    lock = datastore_locks.DatastoreLock(lock_name)
    try:
      lock.Acquire(timeout=RUNTIME_MAX_SECS + 10, max_acquire_attempts=2)
    except datastore_locks.AcquireLockError:
      logging.warning('GenerateMsuUserSummary lock found; exiting.')
      return

    interested_events = self.USER_EVENTS

    lquery = models.ComputerMSULog.all()
    cursor = models.KeyValueCache.MemcacheWrappedGet(
        cursor_name, 'text_value')
    summary, unused_dt = models.ReportsCache.GetMsuUserSummary(
        since=since, tmp=True)

    if cursor and summary:
      lquery.with_cursor(cursor)
    else:
      summary = {}
      for event in interested_events:
        summary[event] = 0
      summary['total_events'] = 0
      summary['total_users'] = 0
      summary['total_uuids'] = 0
      models.ReportsCache.SetMsuUserSummary(
          summary, since=since, tmp=True)

    begin = time.time()
    if now is None:
      now = datetime.datetime.utcnow()

    while True:
      reports = lquery.fetch(self.FETCH_LIMIT)
      if not reports:
        break

      userdata = {}
      last_user = None
      last_user_cursor = None
      prev_user_cursor = None

      n = 0
      for report in reports:
        userdata.setdefault(report.user, {})
        userdata[report.user].setdefault(
            report.uuid, {}).update(
                {report.event: report.mtime})
        if last_user != report.user:
          last_user = report.user
          prev_user_cursor = last_user_cursor
          last_user_cursor = str(lquery.cursor())
        n += 1

      if n == self.FETCH_LIMIT:
        # full fetch, might not have finished this user -- rewind
        del userdata[last_user]
        last_user_cursor = prev_user_cursor

      for user in userdata:
        events = 0
        for uuid in userdata[user]:
          if 'launched' not in userdata[user][uuid]:
            continue
          for event in userdata[user][uuid]:
            if since_days is None or IsTimeDelta(
                userdata[user][uuid][event], now, days=since_days):
              summary.setdefault(event, 0)
              summary[event] += 1
              summary['total_events'] += 1
              events += 1
          if events:
            summary['total_uuids'] += 1
        if events:
          summary['total_users'] += 1
          summary.setdefault('total_users_%d_events' % events, 0)
          summary['total_users_%d_events' % events] += 1

      lquery = models.ComputerMSULog.all()
      lquery.with_cursor(last_user_cursor)

      end = time.time()
      if (end - begin) > RUNTIME_MAX_SECS:
        break

    if reports:
      models.ReportsCache.SetMsuUserSummary(
          summary, since=since, tmp=True)
      models.KeyValueCache.MemcacheWrappedSet(
          cursor_name, 'text_value', last_user_cursor)
      if since_days:
        args = '/%d' % since_days
      else:
        args = ''
      taskqueue.add(
          url='/cron/reports_cache/msu_user_summary%s' % args,
          method='GET',
          countdown=5)
    else:
      models.ReportsCache.SetMsuUserSummary(
          summary, since=since)
      models.KeyValueCache.DeleteMemcacheWrap(
          cursor_name, prop_name='text_value')
      models.ReportsCache.DeleteMsuUserSummary(since=since, tmp=True)

    lock.Release()

  def _GeneratePendingCounts(self):
    """Generates a dictionary of all install names and their pending count."""
    d = {}
    for munki_name in [p.munki_name for p in models.PackageInfo.all()]:
      d[munki_name] = models.Computer.AllActive(keys_only=True).filter(
          'pkgs_to_install =', munki_name).count(999999)
    models.ReportsCache.SetPendingCounts(d)


def _GenerateInstallCounts():
  """Generates a dictionary of all installs names and the count of each."""

  # Obtain a lock.
  lock_name = 'pkgs_list_cron_lock'
  lock = datastore_locks.DatastoreLock(lock_name)
  try:
    lock.Acquire(timeout=600, max_acquire_attempts=1)
  except datastore_locks.AcquireLockError:
    logging.warning('GenerateInstallCounts: lock found; exiting.')
    return

  # Get a list of all packages that have previously been pushed.
  pkgs, unused_dt = models.ReportsCache.GetInstallCounts()

  # Generate a query of all InstallLog entites that haven't been read yet.
  query = models.InstallLog.all().order('server_datetime')
  cursor_obj = models.KeyValueCache.get_by_key_name('pkgs_list_cursor')
  if cursor_obj:
    query.with_cursor(cursor_obj.text_value)

  # Loop over new InstallLog entries.
  try:
    installs = query.fetch(1000)
  except db.Error:
    installs = None
  if not installs:
    models.ReportsCache.SetInstallCounts(pkgs)
    lock.Release()
    return

  for install in installs:
    pkg_name = install.package
    if pkg_name not in pkgs:
      pkgs[pkg_name] = {
          'install_count': 0,
          'install_fail_count': 0,
          'applesus': install.applesus,
      }
    if install.IsSuccess():
      pkgs[pkg_name]['install_count'] = (
          pkgs[pkg_name].setdefault('install_count', 0) + 1)
      # (re)calculate avg_duration_seconds for this package.
      if 'duration_seconds_avg' not in pkgs[pkg_name]:
        pkgs[pkg_name]['duration_count'] = 0
        pkgs[pkg_name]['duration_total_seconds'] = 0
        pkgs[pkg_name]['duration_seconds_avg'] = None
      # only proceed if entity has "duration_seconds" property != None.
      if getattr(install, 'duration_seconds', None) is not None:
        pkgs[pkg_name]['duration_count'] += 1
        pkgs[pkg_name]['duration_total_seconds'] += (
            install.duration_seconds)
        pkgs[pkg_name]['duration_seconds_avg'] = int(
            pkgs[pkg_name]['duration_total_seconds'] /
            pkgs[pkg_name]['duration_count'])
    else:
      pkgs[pkg_name]['install_fail_count'] = (
          pkgs[pkg_name].setdefault('install_fail_count', 0) + 1)

  # Update any changed packages.
  models.ReportsCache.SetInstallCounts(pkgs)

  if not cursor_obj:
    cursor_obj = models.KeyValueCache(key_name='pkgs_list_cursor')

  cursor_txt = str(query.cursor())
  cursor_obj.text_value = cursor_txt
  cursor_obj.put()

  # Delete the lock.
  lock.Release()

  deferred.defer(_GenerateInstallCounts)


def _GenerateTrendingInstallsCacheDeferCallback(
    since_hours, query, cursor, total_success, total_failure,
    trending):
  """Defer task for _GenerateTrendingInstallsCache."""
  installs = query.with_cursor(cursor).fetch(
      summary_module.DEFAULT_COMPUTER_FETCH_LIMIT)
  if installs:
    for install in installs:
      pkg = install.package.encode('utf-8')
      if install.IsSuccess():
        trending['success'][pkg] = trending['success'].setdefault(pkg, 0) + 1
        total_success += 1
      else:
        trending['failure'][pkg] = trending['failure'].setdefault(pkg, 0) + 1
        total_failure += 1

    deferred.defer(
        _GenerateTrendingInstallsCacheDeferCallback, since_hours, query,
        query.cursor(), total_success, total_failure, trending)
    return

  # Get the top trending installs and failures.
  success = sorted(
      trending['success'].items(), key=lambda i: (i[1], i[0]), reverse=True)
  success = success[:TRENDING_INSTALLS_LIMIT]
  success = [(pkg, count, float(count) / total_success * 100)
             for pkg, count in success]
  failure = sorted(
      trending['failure'].items(), key=lambda i: (i[1], i[0]), reverse=True)
  failure = failure[:TRENDING_INSTALLS_LIMIT]
  failure = [(pkg, count, float(count) / total_failure * 100)
             for pkg, count in failure]
  trending = {
      'success': {'packages': success, 'total': total_success},
      'failure': {'packages': failure, 'total': total_failure},
  }
  models.ReportsCache.SetTrendingInstalls(since_hours, trending)


def _GenerateTrendingInstallsCache(since_hours=None):
  """Generates trending install and failure data."""
  if not since_hours:
    since_hours = 1

  trending = {'success': {}, 'failure': {}}
  dt = datetime.datetime.utcnow() - datetime.timedelta(minutes=since_hours * 60)
  query = models.InstallLog.all().filter('mtime >', dt)

  _GenerateTrendingInstallsCacheDeferCallback(
      since_hours, query, None, 0, 0, trending)


def IsTimeDelta(dt1, dt2, seconds=None, minutes=None, hours=None, days=None):
  """Returns delta if datetime values are within a time period.

  Note that only one unit argument may be used at once because of a
  limitation in the way that we process the delta units (only in seconds).

  Args:
    dt1: datetime obj, datetime value 1 to compare
    dt2: datetime obj, datetime value 2 to compare
    seconds: int, optional, within seconds   OR
    minutes: int, optional, within minutes   OR
    hours: int, optional, within minutes     OR
    days: int, optional, without days
  Returns:
    None or datetime.timedelta object
  """
  delta = abs(dt2 - dt1)
  if days is not None:
    dseconds = days * 86400
  elif hours is not None:
    dseconds = hours * 3600
  elif minutes is not None:
    dseconds = minutes * 60
  elif seconds is not None:
    dseconds = seconds
  else:
    return

  if ((delta.days * 86400) + delta.seconds) <= dseconds:
    return delta


def _GenerateComputersSummaryCache(cursor=None, summary=None):
  query = models.Computer.AllActive().with_cursor(cursor)

  computers = query.fetch(summary_module.DEFAULT_COMPUTER_FETCH_LIMIT)
  if computers:
    summary = summary_module.GetComputerSummary(
        computers, initial_summary=summary)
    deferred.defer(_GenerateComputersSummaryCache, query.cursor(), summary)
    return
  models.ReportsCache.SetStatsSummary(
      summary_module.PrepareComputerSummaryForTemplate(summary))
