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
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from simian.mac import common
from simian.mac import models


# list of integer days to keep "days active" counts for.
DAYS_ACTIVE = [1, 7, 14, 30]


class ReportsCache(webapp.RequestHandler):
  """Class to cache reports on a regular basis."""

  def get(self, name=None):
    """Handle GET"""

    if name == 'client_counts':
      self._SetClientCounts()
    elif name == 'summary':
      self._GenerateSummary()
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


def IsWithinPastXHours(datetime_val, hours=24):
  """Returns True if datetime is within past X hours, False otherwise."""
  hours_delta = datetime.timedelta(hours=hours)
  utcnow = datetime.datetime.utcnow()
  if utcnow - datetime_val < hours_delta:
    return True
  return False


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
])


def main():
  if os.environ.get('SERVER_SOFTWARE', '').startswith('Development'):
    logging.getLogger().setLevel(logging.DEBUG)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()