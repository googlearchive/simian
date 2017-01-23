#!/usr/bin/env python
#
# Copyright 2017 Google Inc. All Rights Reserved.
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
"""Admin UI summary generating module."""

import copy
import datetime
import urllib

from  distutils import version as distutils_version
from google.appengine.ext import db

from simian import settings
from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import auth


ACTIVE_DAY_COUNTS = [30, 14, 7, 1]
DEFAULT_COMPUTER_FETCH_LIMIT = 500
REPORT_TYPES = [
    'owner', 'hostname', 'serial', 'uuid', 'client_version', 'os_version']


class Summary(admin.AdminHandler):
  """Handler for /admin/."""

  XSRF_PROTECTION = False

  def get(self):
    """Summary get handler."""
    report_type = self.request.get('filter-type')
    report_filter = self.request.get('filter')

    self_report_username = auth.DoUserAuthWithSelfReportFallback()

    if self_report_username:
      report_type = 'owner'
      report_filter = self_report_username

    if report_type and report_filter:
      report_filter = urllib.unquote(report_filter)
      report_filter = report_filter.strip()
      include_inactive = bool(self.request.get('include-inactive'))
      self._DisplaySummary(
          report_type, report_filter, include_inactive,
          bool(self_report_username))
    else:
      self._DisplayCachedSummary()

  def _DisplayCachedSummary(self):
    """Displays stats summary from cached dict."""
    summary, mtime = models.ReportsCache.GetStatsSummary()

    trend_hour, trend_hour_mtime = models.ReportsCache.GetTrendingInstalls(1)
    trend_day, trend_day_mtime = models.ReportsCache.GetTrendingInstalls(24)
    trending_installs = [
        (1, trend_hour, trend_hour_mtime),
        (24, trend_day, trend_day_mtime),
    ]
    values = {
        'summary': summary, 'cached_mtime': mtime, 'report_type': 'summary',
        'trending_installs': trending_installs,
        'client_site_enabled': settings.CLIENT_SITE_ENABLED,
    }
    self.Render('summary.html', values)

  def _DisplaySummary(
      self, report_type, report_filter, include_inactive, self_report):
    """Displays stats summary for a given track or site.

    Args:
      report_type: str report type being requested.
      report_filter: str report filter to apply to the type.
      include_inactive: bool, True to include inactive hosts.
      self_report: bool, True to enable self report
    """
    default_limit = DEFAULT_COMPUTER_FETCH_LIMIT
    computers = None
    if include_inactive:
      query = models.Computer.all()
    else:
      query = models.Computer.AllActive()

    if report_type == 'track':
      query.filter('track =', report_filter).order('-preflight_datetime')
    elif report_type == 'site':
      if report_filter == 'None':
        report_filter = None
      query.filter('site =', report_filter).order('-preflight_datetime')
      default_limit = 2000  # Show all clients in most sites.
    elif report_type == 'tag':
      tag = models.Tag.get_by_key_name(report_filter)
      if tag:
        computers = [db.get(key) for key in tag.keys]
      else:
        computers = []
    elif report_type == 'group':
      group = models.Group.get_by_key_name(report_filter)
      if group:
        query.filter('owner IN', group.users)
      else:
        computers = []
    elif report_type in REPORT_TYPES:
      query.filter('%s =' % report_type, report_filter)
    else:
      self.response.out.write('unknown report_type: %s' % report_type)
      return

    if computers is None:
      computers = self.Paginate(query, default_limit)

    if len(computers) == 1:
      msg = 'Your search only matched a single host.'
      self.redirect('/admin/host/%s?msg=%s' % (computers[0].uuid, msg))
      return

    # If we didn't get a sorted query from Datastore, sort now.
    if report_type in REPORT_TYPES:
      computers.sort(key=lambda c: c.preflight_datetime, reverse=True)

    try:
      owner_lookup_url = settings.OWNER_LOOKUP_URL
    except AttributeError:
      owner_lookup_url = None

    summary = PrepareComputerSummaryForTemplate(
        GetComputerSummary(computers=computers))
    values = {
        'computers': computers, 'summary': summary, 'report_type': 'search',
        'search_type': report_type, 'search_term': report_filter,
        'owner_lookup_url': owner_lookup_url, 'self_report': self_report,
        'client_site_enabled': settings.CLIENT_SITE_ENABLED,
    }
    self.Render('summary.html', values)


def PrepareComputerSummaryForTemplate(s):
  """Prepare data produced by GetComputerSummary for template."""
  summary = copy.deepcopy(s)

  summary['sites_histogram'] = DictToList(
      summary['sites_histogram'], reverse=True, by_value=True)
  summary['os_versions'] = DictToList(summary['os_versions'], version=True)
  summary['client_versions'] = DictToList(
      summary['client_versions'], version=True)

  # set summary connection counts and percentages.
  total_connections = summary['conns_on_corp'] + summary['conns_off_corp']
  if total_connections:
    summary['conns_on_corp_percent'] = (
        summary['conns_on_corp'] * 100.0 / total_connections)
    summary['conns_off_corp_percent'] = (
        summary['conns_off_corp'] * 100.0 / total_connections)
  else:
    summary['conns_on_corp_percent'] = 0
    summary['conns_off_corp_percent'] = 0

  # calculate all_(apple_updates|pkgs)_installed_percent values.
  for days in ACTIVE_DAY_COUNTS:
    summary['all_pkgs_installed_percent'][days] = GetPercentage(
        summary['all_pkgs_installed'][days], summary['active'][days])
    summary['all_apple_updates_installed_percent'][days] = GetPercentage(
        summary['all_apple_updates_installed'][days], summary['active'][days])

  if summary['active'][30]:
    return summary
  else:
    return {}


def GetComputerSummary(computers, initial_summary=None):
  """Generates a summary overview of all computers in a given query.

  Args:
    computers: list of Computer objects to generate a summary of.
    initial_summary: optional, dict, initial value for summary.
  Returns:
    dict, stats summary data.
  """
  if not initial_summary:
    summary = {
        'active': {},
        'all_pkgs_installed': {},
        'all_pkgs_installed_percent': {},
        'all_apple_updates_installed': {},
        'all_apple_updates_installed_percent': {},
        'conns_on_corp': 0,
        'conns_off_corp': 0,
        'conns_on_corp_percent': None,
        'conns_off_corp_percent': None,
        'tracks': {},
        'os_versions': {},
        'client_versions': {},
        'sites_histogram': {},
    }
    # initialize active counts dictionaries.
    for days in ACTIVE_DAY_COUNTS:
      summary['active'][days] = 0
      summary['all_pkgs_installed'][days] = 0
      summary['all_apple_updates_installed'][days] = 0
      for track in common.TRACKS:
        summary['tracks'][track] = {}
        summary['tracks'][track][days] = 0
  else:
    summary = copy.deepcopy(initial_summary)

  # even though Tasks can now run up to 10 minutes, Datastore queries are
  # still limited to 30 seconds (2010-10-27). Treating a QuerySet as an
  # iterator also trips this restriction, so fetch 500 at a time.
  for c in computers:
    # copy property values to new str, so computer object isn't kept in
    # memory for the sake of dict key storage.
    os_version = str(c.os_version)
    client_version = str(c.client_version)
    site = str(c.site)

    summary['conns_on_corp'] += c.connections_on_corp
    summary['conns_off_corp'] += c.connections_off_corp
    summary['os_versions'][os_version] = summary['os_versions'].get(
        os_version, 0) + 1
    summary['client_versions'][client_version] = (
        summary['client_versions'].get(client_version, 0) + 1)

    for days in ACTIVE_DAY_COUNTS:
      if IsWithinPastXHours(c.preflight_datetime, days * 24):
        summary['active'][days] += 1
        track_count = summary['tracks'][c.track].get(days, 0)
        summary['tracks'][c.track][days] = track_count + 1
        if c.all_pkgs_installed:
          summary['all_pkgs_installed'][days] += 1
        if getattr(c, 'all_apple_updates_installed', False):
          summary['all_apple_updates_installed'][days] += 1
      else:
        break

    summary['sites_histogram'][site] = (
        summary['sites_histogram'].get(site, 0) + 1)

  return summary


def GetPercentage(number, total):
  """Returns the float percentage that a number is of a total."""
  if not number:
    return 0
  return float(number) / total * 100


def DictToList(d, sort=True, reverse=True, by_value=False, version=False):
  """Converts a dict to a list of tuples.

  Args:
    d: dictionary to convert to a list.
    sort: Boolean default True, to sort based on dict key or not.
    reverse: Boolean default True, to reverse the order or not.
    by_value: Boolean default False, to sort based on dict values.
    version: Boolean default False, to sort based on version string.
  Returns:
    List of tuples [(dict key, dict value),...]
  """
  l = [(k, v) for k, v in d.iteritems()]
  if sort and by_value:
    l.sort(key=lambda t: t[1])
  if sort and version:
    l.sort(key=lambda t: distutils_version.LooseVersion(t[0]))
  elif sort:
    l.sort()
  if reverse:
    l.reverse()
  return l


def IsWithinPastXHours(datetime_val, hours=24):
  """Returns True if datetime is within past X hours, False otherwise."""
  hours_delta = datetime.timedelta(hours=hours)
  utcnow = datetime.datetime.utcnow()
  if utcnow - datetime_val < hours_delta:
    return True
  return False
