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

"""Admin stats handler."""





import datetime
import os
import re
import time
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from simian import settings
from simian.mac import models
from simian.mac.common import auth
from simian.mac.munki import plist


COMPUTER_FETCH_LIMIT = 1000
INSTALL_LOG_FETCH_LIMIT = 2000
PREFLIGHT_EXIT_LOG_FETCH_LIMIT = 2000
REPORT_TYPES = ['owner', 'hostname', 'uuid', 'client_version', 'os_version']


class UTCTZ(datetime.tzinfo):
  """tzinfo class for the UTC time zone."""

  def tzname(self, unused_dt):
    return 'UTC'

  def dst(self, unused_dt):
    return datetime.timedelta(0)

  def utcoffset(self, unused_dt):
    return datetime.timedelta(0)


class Stats(webapp.RequestHandler):
  """"Handler for /admin/stats."""

  def get(self, report=None, uuid=None):
    """Stats get handler."""
    auth.DoUserAuth()
    if not report:
      report_type = self.request.get('type')
      report_filter = self.request.get('filter')
      if report_type and report_filter:
        report_filter = report_filter.strip()
        self._DisplaySummary(report_type, report_filter)
      else:
        self._DisplayCachedSummary()
    elif report == 'host':
      self._DisplayHost(uuid=uuid)
    elif report == 'installs':
      pkg = self.request.get('pkg')
      if pkg:
        self._DisplayInstallsForPackage(pkg)
      else:
        self._DisplayPackagesList()
    elif report == 'installproblems':
      self._DisplayInstallProblems()
    elif report == 'preflightexits':
      self._DisplayPreflightExits()
    elif report == 'diskfree':
      self._DisplayLowDiskFree()
    elif report == 'uptime':
      self._DisplayLongestUptime()
    elif report == 'brokenclients':
      self._DisplayBrokenClients()
    else:
      self.response.set_status(404)

  def _Paginate(self, query, limit):
    """Returns a list of entities limited to limit, with a next_page cursor."""
    if self.request.get('page', ''):
      query.with_cursor(self.request.get('page'))
    entities = list(query.fetch(limit))
    if len(entities) == limit:
      next_page = query.cursor()
    else:
      next_page = None
    return entities, next_page

  def _DisplayCachedSummary(self):
    """Displays stats summary from cached dict."""
    summary, mtime = models.ReportsCache.GetStatsSummary()
    values = {'summary': summary, 'cached': True, 'mtime': mtime}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

  def _DisplaySummary(self, report_type, report_filter):
    """Displays stats summary for a given track or site.

    Args:
      report_type: str report type being requested.
      report_filter: str report filter to apply to the type.
    """
    if report_type == 'track':
      query = models.Computer.AllActive().filter(
          'track =', report_filter).order('-preflight_datetime')
    elif report_type == 'site':
      if report_filter == 'None':
        report_filter = None
      query = models.Computer.AllActive().filter(
          'site =', report_filter).order('-preflight_datetime')
    elif report_type in REPORT_TYPES:
      query = models.Computer.AllActive().filter(
          '%s =' % report_type, report_filter)
    else:
      self.response.out.write('unknown report_type: %s' % report_type)
      return

    computers, next_page = self._Paginate(query, COMPUTER_FETCH_LIMIT)
    if len(computers) == 1:
      self._DisplayHost(computer=computers[0])
      return

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
      summary['active'] += 1
      connections_on_corp += c.connections_on_corp
      connections_off_corp += c.connections_off_corp
      tracks[c.track] = tracks.get(c.track, 0) + 1
      os_versions[c.os_version] = os_versions.get(
          c.os_version, 0) + 1
      client_versions[c.client_version] = (
          client_versions.get(c.client_version, 0) + 1)

      if c.connection_datetimes:
        for days in [14, 7, 1]:
          if IsWithinPastXHours(c.connection_datetimes[-1], days * 24):
            summary['active_%dd' % days] += 1
          else:
            break

      summary['sites_histogram'][c.site] = (
          summary['sites_histogram'].get(c.site, 0) + 1)

      AddTimezoneToComputerDatetimes(c)

      c.connection_datetimes.reverse()
      c.connection_dates.reverse()

    # Convert connections histogram to percentages.
    off_corp_connections_histogram_percent = []
    for bucket, count in self._DictToList(off_corp_connections_histogram):
      if not summary['active']:
        percent = 0
      else:
        percent = float(count) / summary['active'] * 100.0
      off_corp_connections_histogram_percent.append((bucket, percent))
    summary['off_corp_conns_histogram'] = off_corp_connections_histogram_percent

    summary['sites_histogram'] = self._DictToList(
        summary['sites_histogram'], reverse=False)
    summary['tracks'] = self._DictToList(tracks, reverse=False)
    summary['os_versions'] = self._DictToList(os_versions)
    summary['client_versions'] = self._DictToList(client_versions)

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

    values = {'computers': computers, 'summary': summary,
              'report_type': report_type, 'report_filter': report_filter,
              'cached': False, 'next_page': next_page,
              'owner_lookup_url': settings.OWNER_LOOKUP_URL,
              'limit': COMPUTER_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

  def _DictToList(self, d, sort=True, reverse=True):
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

  def _DisplayHost(self, uuid=None, computer=None):
    """Displays the report for a single host.

    Args:
      uuid: str uuid for host to display.
      computer: models.Computer object to display.
    """
    if not computer:
      computer = models.Computer.get_by_key_name(uuid)
    else:
      uuid = computer.uuid
    msu_log = models.ComputerMSULog.all().filter('uuid =', uuid).order('-mtime')
    installs = models.InstallLog.all().filter('uuid =', uuid).order('-mtime')
    exits = models.PreflightExitLog.all().filter('uuid =', uuid).order(
        '-mtime').fetch(PREFLIGHT_EXIT_LOG_FETCH_LIMIT)
    install_problems = models.ClientLog.all().filter(
        'action =', 'install_problem').filter('uuid =', uuid).order(
            '-mtime').fetch(INSTALL_LOG_FETCH_LIMIT)
    uptime = None
    if computer:
      AddTimezoneToComputerDatetimes(computer)
      computer.connection_dates.reverse()
      computer.connection_datetimes.reverse()
      if computer.uptime:
        uptime_days = datetime.timedelta(seconds=computer.uptime).days
        uptime_hms = time.strftime('%H:%M:%S', time.gmtime(computer.uptime))
        uptime = '%d days, %s' % (uptime_days, uptime_hms)
      else:
        uptime = 'unknown'

    values = {
        'uuid_lookup_url': settings.UUID_LOOKUP_URL,
        'owner_lookup_url': settings.OWNER_LOOKUP_URL,
        'computer': computer,
        'installs': list(installs),
        'msu_log': msu_log,
        'install_problems': install_problems,
        'preflight_exits': exits,
        'uptime': uptime,
        'host_report': True
    }
    self.response.out.write(RenderTemplate('templates/stats_host.html', values))

  def _DisplayPackagesList(self):
    """Displays list of all installs/removals/etc."""
    packages = []
    for p in models.PackageInfo.all().order('name'):
      pl = plist.MunkiPackageInfoPlist(p.plist)
      pl.Parse()
      pl_dict = pl.GetContents()
      if 'display_name' in pl_dict:
        munki_name = '%s-%s' % (pl_dict['display_name'], pl_dict['version'])
      else:
        munki_name = '%s-%s' % (pl_dict['name'], pl_dict['version'])

      pkg = {}
      pkg['forced'] = pl_dict.get('forced_install', False)
      pkg['munki_install_name'] = munki_name
      pkg['catalogs'] = p.catalogs
      pkg['manifests'] = p.manifests
      pkg['filename'] = p.filename
      pkg['install_types'] = p.install_types
      pkg['description'] = pl_dict['description']
      packages.append(pkg)
    self.response.out.write(
        RenderTemplate('templates/stats_installs.html', {'packages': packages}))

  def _DisplayInstallsForPackage(self, pkg):
    """Displays a list of installs of a particular package."""
    query = models.InstallLog.all().filter('package =', pkg).order(
        '-mtime')
    installs, next_page = self._Paginate(query, INSTALL_LOG_FETCH_LIMIT)
    values = {'installs': installs, 'pkg': pkg, 'next_page': next_page,
              'limit': INSTALL_LOG_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_installs.html', values))

  def _DisplayInstallProblems(self):
    """Displays all installation problems."""
    query = models.ClientLog.all().filter('action =', 'install_problem').order(
        '-mtime')
    problems, next_page = self._Paginate(query, INSTALL_LOG_FETCH_LIMIT)
    values = {'install_problems': problems, 'next_page': next_page,
              'limit': INSTALL_LOG_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_installproblems.html', values))

  def _DisplayPreflightExits(self):
    """Displays all preflight exits."""
    query = models.PreflightExitLog.all().order('-mtime')
    exits, next_page = self._Paginate(query, PREFLIGHT_EXIT_LOG_FETCH_LIMIT)
    values = {'preflight_exits': exits, 'next_page': next_page,
              'limit': PREFLIGHT_EXIT_LOG_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_preflightexits.html', values))

  def _DisplayLowDiskFree(self):
    """Displays a report of machines with lowest disk space."""
    computers = models.Computer.AllActive().filter(
        'root_disk_free !=', None).order('root_disk_free').fetch(
            COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'diskfree',
              'cached': False, 'limit': COMPUTER_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

  def _DisplayLongestUptime(self):
    """Displays a report of machines with longest uptime."""
    computers = models.Computer.AllActive().filter(
        'uptime !=', None).order('-uptime').fetch(
            COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'uptime',
              'cached': False, 'limit': COMPUTER_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

  def _DisplayBrokenClients(self):
    """Displays a report of broken clients."""
    computers = models.ComputerClientBroken.all().filter('fixed =', False)
    computers = list(computers)
    for computer in computers:
      computer.details = computer.details.replace("'", "\\'")
      computer.details = computer.details.replace('"', "\\'")
      computer.details = re.sub('\n', '<br/>', computer.details)
      computer.broken_datetimes.reverse()
    self.response.out.write(RenderTemplate(
        'templates/stats_brokenclients.html', {'computers': computers}))


def IsWithinPastXHours(datetime_val, hours=24):
  """Returns True if datetime is within past X hours, False otherwise."""
  hours_delta = datetime.timedelta(hours=hours)
  utcnow = datetime.datetime.utcnow()
  if utcnow - datetime_val < hours_delta:
    return True
  return False


def AddTimezoneToComputerDatetimes(computer):
  """Sets the tzinfo on all Computer.connected_datetimes for use with Django.

  Args:
    computer: models.Computer entity.
  Returns:
    Boolean. True if one date is today, false otherwise.
  """
  for i in xrange(0, len(computer.connection_datetimes)):
    cdt = computer.connection_datetimes[i]
    # set timezone so Django "timesince" template filter works.
    computer.connection_datetimes[i] = datetime.datetime(
        cdt.year, cdt.month, cdt.day,
        cdt.hour, cdt.minute, cdt.second,
        tzinfo=UTCTZ())


def RenderTemplate(template_path, values):
  """Renders a template using supplied data values and returns HTML.

  Args:
    template_path: str path of template.
    values: dict of template values.
  Returns:
    str HTML of rendered template.
  """
  path = os.path.join(
      os.path.dirname(__file__), template_path)
  return template.render(path, values)