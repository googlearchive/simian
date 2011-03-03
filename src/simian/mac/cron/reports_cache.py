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

"""Module containing url handler for report calculation.

Classes:
  ReportsCache: the url handler
"""



import datetime
import gc
import logging
import os
import time
from google.appengine.ext import webapp
from google.appengine.api import taskqueue
from google.appengine.ext.webapp.util import run_wsgi_app
from simian.mac import common
from simian.mac import models
from simian.mac.munki import plist


# list of integer days to keep "days active" counts for.
DAYS_ACTIVE = [1, 7, 14, 30]


class ReportsCache(webapp.RequestHandler):
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
    """Handle GET"""

    if name == 'client_counts':
      self._SetClientCounts()
    elif name == 'summary':
      self._GenerateSummary()
    elif name == 'installcounts':
      self._GenerateInstallCounts()
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
      self.response.set_status(404)

  def _SetClientCounts(self):
    """Generates and sets various client counts to ReportsCache in Datastore."""
    total = 0
    for track in common.TRACKS:
      n = models.Computer.AllActive(keys_only=True).filter(
          'track =', track).count()
      models.ReportsCache.SetClientCount(n, 'track', track)
      logging.debug('SetClientCounts for %s track: %d', track, n)
      total += n
    models.ReportsCache.SetClientCount(total)
    logging.debug('SetClientCounts for all clients: %s', total)

    now = datetime.datetime.utcnow()
    for days in DAYS_ACTIVE:
      x_days_ago = now - datetime.timedelta(days=days)
      n = models.Computer.AllActive(keys_only=True).filter(
          'preflight_datetime >', x_days_ago).count()
      models.ReportsCache.SetClientCount(n, 'days_active', days)
      logging.debug('SetClientCounts for %d day actives: %d', days, n)

  def _GenerateSummary(self):
    """Generates a summary and saves to Datastore for stats summary output."""
    summary = {
        'active': 0,
        'active_1d': 0,
        'active_7d': 0,
        'active_14d': 0,
        'conns_on_corp': None,
        'conns_off_corp': None,
        'conns_on_corp_percent': None,
        'conns_off_corp_percent': None,
        'tracks': {},
        'os_versions': {},
        'client_versions': {},
        'off_corp_conns_histogram': {},
        'sites_histogram': {},
    }
    tracks = {}
    os_versions = {}
    client_versions = {}
    connections_on_corp = 0
    connections_off_corp = 0
    off_corp_connections_histogram = {}

    # intialize corp connections histogram buckets.
    for i in xrange(0, 10):
      bucket = ' %s0-%s9' % (i, i)
      off_corp_connections_histogram[bucket] = 0
    off_corp_connections_histogram['100'] = 0
    off_corp_connections_histogram[' -never-'] = 0

    query = models.Computer.AllActive()
    # even though Tasks can now run up to 10 minutes, Datastore queries are
    # still limited to 30 seconds (2010-10-27). Treating a QuerySet as an
    # iterator also trips this restriction, so fetch 1000 at a time.
    while True:
      computers = query.fetch(500)
      gc.collect()
      if not computers:
        break

      for c in computers:
        if c.connections_off_corp:
          # calculate percentage off corp.
          percent_off_corp = (float(c.connections_off_corp) / (
              c.connections_off_corp + c.connections_on_corp))
          # group into buckets; 0-9, 10-19, 20-29, ..., 90-99, 100.
          bucket_number = int(percent_off_corp * 10)
          if bucket_number == 10:  # bucket 100% into their own
            bucket = '100'
          else:
            bucket = ' %s0-%s9' % (bucket_number, bucket_number)
        else:
          bucket = ' -never-'
        off_corp_connections_histogram[bucket] += 1

        # copy property values to new str, so computer object isn't kept in
        # memory for the sake of dict key storage.
        track = str(c.track)
        os_version = str(c.os_version)
        client_version = str(c.client_version)
        site = str(c.site)

        summary['active'] += 1
        connections_on_corp += c.connections_on_corp
        connections_off_corp += c.connections_off_corp
        tracks[track] = tracks.get(track, 0) + 1
        os_versions[os_version] = os_versions.get(os_version, 0) + 1
        client_versions[client_version] = (
            client_versions.get(client_version, 0) + 1)

        if c.connection_datetimes:
          for days in [14, 7, 1]:
            if IsWithinPastXHours(c.connection_datetimes[-1], days * 24):
              summary['active_%dd' % days] += 1
            else:
              break

        summary['sites_histogram'][site] = (
            summary['sites_histogram'].get(site, 0) + 1)

      del(computers)
      cursor = str(query.cursor())
      del(query)
      gc.collect()
      query = models.Computer.AllActive()
      query.with_cursor(cursor)  # queue up the next fetch

    # Convert connections histogram to percentages.
    off_corp_connections_histogram_percent = []
    for bucket, count in DictToList(off_corp_connections_histogram):
      if not summary['active']:
        percent = 0
      else:
        percent = float(count) / summary['active'] * 100
      off_corp_connections_histogram_percent.append((bucket, percent))
    summary['off_corp_conns_histogram'] = off_corp_connections_histogram_percent

    summary['sites_histogram'] = DictToList(
        summary['sites_histogram'], reverse=False)
    summary['tracks'] = DictToList(tracks, reverse=False)
    summary['os_versions'] = DictToList(os_versions)
    summary['client_versions'] = DictToList(client_versions)

    # set summary connection counts and percentages.
    summary['conns_on_corp'] = connections_on_corp
    summary['conns_off_corp'] = connections_off_corp
    total_connections = connections_on_corp + connections_off_corp
    if total_connections:
      summary['conns_on_corp_percent'] = (
          connections_on_corp * 100.0 / total_connections)
      summary['conns_off_corp_percent'] = (
          connections_off_corp * 100.0 / total_connections)
    else:
      summary['conns_on_corp_percent'] = 0
      summary['conns_off_corp_percent'] = 0

    logging.debug('Saving stats summary to Datastore: %s', summary)
    models.ReportsCache.SetStatsSummary(summary)

  def _GenerateMsuUserSummary(self, since_days=None, now=None):
    """Generate summary of MSU user data.

    Args:
      since_days: int, optional, only report on the last x days
      now: datetime.datetime, optional, supply an alternative
        value for the current date/time
    """
    # TODO: when running from a taskqueue, this value could be higher.
    RUNTIME_MAX_SECS = 15

    cursor_name = 'msu_user_summary_cursor'

    if since_days is None:
      since = None
    else:
      since = '%dD' % since_days
      cursor_name = '%s_%s' % (cursor_name, since)

    interested_events = self.USER_EVENTS

    lquery = models.ComputerMSULog.all()
    cursor = models.KeyValueCache.MemcacheWrappedGet(
        cursor_name, 'text_value')
    summary = models.ReportsCache.GetMsuUserSummary(
        since=since, tmp=True)

    if cursor and summary:
      lquery.with_cursor(cursor)
      summary = summary[0]
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
        del(userdata[last_user])
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
      models.KeyValueCache.ResetMemcacheWrap(cursor_name)
      summary_tmp = models.ReportsCache.DeleteMsuUserSummary(
          since=since, tmp=True)

  def _GenerateInstallCounts(self):
    """Generate install counts reports cache."""
    install_counts = {}
    for p in models.PackageInfo.all().order('name'):
      pl = plist.MunkiPackageInfoPlist(p.plist)
      pl.Parse()
      pl_dict = pl.GetContents()
      if 'display_name' in pl_dict:
        munki_name = '%s-%s' % (pl_dict['display_name'], pl_dict['version'])
      else:
        munki_name = '%s-%s' % (pl_dict['name'], pl_dict['version'])

      count = models.InstallLog.all(keys_only=True).filter(
          'package =', munki_name).count(999999)
      install_counts[munki_name] = count
    models.ReportsCache.SetInstallCounts(install_counts)


def IsWithinPastXHours(datetime_val, hours=24):
  """Returns True if datetime is within past X hours, False otherwise."""
  hours_delta = datetime.timedelta(hours=hours)
  utcnow = datetime.datetime.utcnow()
  if utcnow - datetime_val < hours_delta:
    return True
  return False


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

def DictToList(d, sort=True, reverse=True):
  """Converts a dict to a list of tuples.

  Args:
    d: dictionary to convert to a list.
    sort: Boolean default True, to sort based on dict key or not.
    reverse: Boolean default True, to reverse the order or not.
  Returns:
    List of tuples [(dict key, dict value),...]
  """
  l = [(k, v) for k, v in d.iteritems()]
  if sort:
    l.sort()
  if reverse:
    l.reverse()
  return l


application = webapp.WSGIApplication([
    (r'/cron/reports_cache/([a-z_]+)$', ReportsCache),
    (r'/cron/reports_cache/([a-z_]+)/(.*)$', ReportsCache),
])


def main():
  if os.environ.get('SERVER_SOFTWARE', '').startswith('Development'):
    logging.getLogger().setLevel(logging.DEBUG)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()