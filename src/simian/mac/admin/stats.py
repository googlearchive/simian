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

"""Admin handler."""





import datetime
import logging
import os
import re
import time
import urllib
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from simian import settings
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import util
from simian.mac.munki import plist
from simian.mac.munki import common

COMPUTER_FETCH_LIMIT = 1000
USER_SETTINGS_FETCH_LIMIT = 500
ADMIN_LOG_FETCH_LIMIT = 2000
INSTALL_LOG_FETCH_LIMIT = 2000
PREFLIGHT_EXIT_LOG_FETCH_LIMIT = 2000
SINGLE_HOST_DATA_FETCH_LIMIT = 500
MSU_LOG_EVENT_LIMIT = 1000
REPORT_TYPES = [
    'owner', 'hostname', 'serial', 'uuid', 'client_version', 'os_version']


class UTCTZ(datetime.tzinfo):
  """tzinfo class for the UTC time zone."""

  def tzname(self, unused_dt):
    return 'UTC'

  def dst(self, unused_dt):
    return datetime.timedelta(0)

  def utcoffset(self, unused_dt):
    return datetime.timedelta(0)


class Stats(webapp.RequestHandler):
  """"Handler for /admin."""

  def post(self, report=None, uuid=None):
    """Stats post handler."""
    #logging.debug('POST called: report=%s, uuid=%s', report, uuid)
    if not auth.IsAdminUser() and not auth.IsSupportStaff():
      self.response.set_status(403)
      return

    if report not in ['host', 'clientlog', 'brokenclients']:
      self.response.set_status(404)
      return

    action = self.request.get('action')
    if action == 'set_inactive':
      c = models.Computer.get_by_key_name(uuid)
      if not c:
        self.response.out.write('UUID not found')
        return
      c.active = False
      c.put(update_active=False)
    elif action == 'set_loststolen':
      models.ComputerLostStolen.SetLostStolen(uuid)
    elif action == 'upload_logs':
      c = models.Computer.get_by_key_name(uuid)
      if not c:
        self.response.out.write('UUID not found')
        return
      c.upload_logs_and_notify = users.get_current_user().email()
      c.put()
    elif action == 'delete_client_log':
      key = uuid  # for /admin/clientlog/ it's really the uuid_logname
      l = models.ClientLogFile.get_by_key_name(key)
      l.delete()
      return
    elif action == 'set_fixed':
      c = models.ComputerClientBroken.get_by_key_name(uuid)
      if not c:
        self.response.out.write('UUID not found')
        return
      c.fixed = True
      c.put()
    else:
      self.response.set_status(404)

    self.redirect('/admin/%s/%s' % (report, uuid))

  def get(self, report=None, uuid=None):
    """Stats get handler."""
    auth.DoUserAuth()
    if not report:
      report_type = self.request.get('type')
      report_filter = self.request.get('filter')
      if report_type and report_filter:
        report_filter = urllib.unquote(report_filter)
        report_filter = report_filter.strip()
        self._DisplaySummary(report_type, report_filter)
      else:
        self._DisplayCachedSummary()
    elif report == 'host':
      self._DisplayHost(uuid=uuid)
    elif report == 'hostmanifest':
      self._DisplayHostManifest(uuid=uuid)
    elif report == 'installs':
      pkg = self.request.get('pkg')
      historical = self.request.get('historical') == '1'
      applesus = self.request.get('applesus') == '1'
      pending = self.request.get('pending') == '1'
      if pkg:
        if pending:
          self._DisplayHostsPendingPkg(pkg)
        else:
          self._DisplayInstallsForPackage(pkg)
      else:
        if historical or applesus:
          self._DisplayPackagesListFromCache(applesus=applesus)
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
    elif report == 'offcorp':
      self._DisplayLongestOffCorp()
    elif report == 'brokenclients':
      self._DisplayBrokenClients()
    elif report == 'msulogsummary':
      self._DisplayMsuLogSummary(since_days=uuid)
    elif report == 'msulogevent':
      self._DisplayMsuLogEvent()
    elif report == 'user_settings':
      self._DisplayUserSettings()
    elif report == 'adminlogs':
      self._DisplayAdminLogs()
    elif report == 'loststolen':
      self._DisplayLostStolen()
    elif report == 'packagealias':
      self._DisplayPackageAlias()
    elif report == 'clientlog':
      log_key_name = uuid
      l = models.ClientLogFile.get_by_key_name(log_key_name)
      if l:
        self.response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        self.response.out.write(l.log_file)
      else:
        self.response.out.write('Log not found')
        self.response.set_status(404)
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
      self.redirect('/admin/host/%s' % computers[0].uuid)
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
    client_log_files = models.ClientLogFile.all().filter('uuid =', uuid).order(
        '-mtime').fetch(100)
    msu_log = models.ComputerMSULog.all().filter('uuid =', uuid).order(
        '-mtime').fetch(100)
    applesus_installs = models.InstallLog.all().filter('uuid =', uuid).filter(
        'applesus =', True).order('-mtime').fetch(SINGLE_HOST_DATA_FETCH_LIMIT)
    installs = models.InstallLog.all().filter('uuid =', uuid).filter(
        'applesus =', False).order('-mtime').fetch(SINGLE_HOST_DATA_FETCH_LIMIT)
    exits = models.PreflightExitLog.all().filter('uuid =', uuid).order(
        '-mtime').fetch(SINGLE_HOST_DATA_FETCH_LIMIT)
    install_problems = models.ClientLog.all().filter(
        'action =', 'install_problem').filter('uuid =', uuid).order(
            '-mtime').fetch(SINGLE_HOST_DATA_FETCH_LIMIT)
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
        'applesus_installs': applesus_installs,
        'installs': installs,
        'client_log_files': client_log_files,
        'msu_log': msu_log,
        'install_problems': install_problems,
        'preflight_exits': exits,
        'uptime': uptime,
        'host_report': True,
        'limit': SINGLE_HOST_DATA_FETCH_LIMIT,
        'is_admin': auth.IsAdminUser(),
        'is_support_staff': auth.IsSupportStaff(),
    }
    self.response.out.write(RenderTemplate('templates/stats_host.html', values))

  def _DisplayPackagesList(self):
    """Displays list of all installs/removals/etc."""
    installs, counts_mtime = models.ReportsCache.GetInstallCounts()
    packages = []
    for p in models.PackageInfo.all():
      pl = plist.MunkiPackageInfoPlist(p.plist)
      pl.Parse()

      pkg = {}
      pkg['count'] = installs.get(p.munki_name, {}).get('install_count', 'N/A')
      pkg['duration_seconds_avg'] = installs.get(p.munki_name, {}).get(
          'duration_seconds_avg', None) or 'N/A'
      pkg['unattended'] = pl.get('unattended_install', False)
      force_install_after_date = pl.get('force_install_after_date', None)
      if force_install_after_date:
        pkg['force_install_after_date'] = force_install_after_date
      pkg['catalogs'] = p.catalogs
      pkg['manifests'] = p.manifests
      pkg['munki_name'] = p.munki_name or pl.GetMunkiName()
      pkg['filename'] = p.filename
      pkg['install_types'] = p.install_types
      pkg['description'] = pl['description']
      packages.append(pkg)

    packages.sort(key=lambda pkg: pkg['munki_name'].lower())
    self.response.out.write(
        RenderTemplate('templates/stats_installs.html',
        {'packages': packages, 'counts_mtime': counts_mtime}))

  def _DisplayPackagesListFromCache(self, applesus=False):
    installs, counts_mtime = models.ReportsCache.GetInstallCounts()
    pkgs = []
    names = installs.keys()
    names.sort()
    for name in names:
      install = installs[name]
      if applesus and install['applesus']:
        d = {'name': name,
             'count': install['install_count'],
             'duration_seconds_avg': install.get('duration_seconds_avg', 'N/A')
        }
        pkgs.append(d)
      elif not applesus and not install['applesus']:
        d = {'name': name,
             'count': install['install_count'],
             'duration_seconds_avg': install.get('duration_seconds_avg', 'N/A')
        }
        pkgs.append(d)
    self.response.out.write(
        RenderTemplate('templates/stats_installs.html',
        {'packages': pkgs, 'counts_mtime': counts_mtime,
         'applesus': applesus, 'cached_pkgs_list': True}))

  def _DisplayInstallsForPackage(self, pkg):
    """Displays a list of installs of a particular package."""
    applesus = self.request.get('applesus') == '1'
    if pkg == 'all':
      if applesus:
        query = models.InstallLog.all().filter(
            'applesus =', True).order('-mtime')
      else:
        query = models.InstallLog.all().filter(
            'applesus =', False).order('-mtime')
    else:
      query = models.InstallLog.all().filter('package =', pkg).order(
          '-mtime')
    installs, next_page = self._Paginate(query, INSTALL_LOG_FETCH_LIMIT)
    values = {'installs': installs, 'pkg': pkg, 'next_page': next_page,
              'limit': INSTALL_LOG_FETCH_LIMIT, 'applesus': applesus}
    self.response.out.write(
        RenderTemplate('templates/stats_installs.html', values))

  def _DisplayHostsPendingPkg(self, pkg):
    """Displays a list of hosts where pkg is pending installation."""
    query = models.Computer.AllActive().filter('pkgs_to_install =', pkg)
    computers, next_page = self._Paginate(query, COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'pkg': pkg, 'next_page': next_page,
              'cached': False, 'report_type': 'pkgs_to_install',
              'limit': COMPUTER_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

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
        'root_disk_free !=', None).filter('root_disk_free !=', 0).order(
            'root_disk_free').fetch(COMPUTER_FETCH_LIMIT)
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

  def _DisplayLongestOffCorp(self):
    """Displays a report of machines with longest off corp time."""
    computers = models.Computer.AllActive().filter(
        'last_on_corp_preflight_datetime !=', None).order(
            'last_on_corp_preflight_datetime').fetch(
                COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'offcorp',
              'cached': False, 'limit': COMPUTER_FETCH_LIMIT}
    self.response.out.write(
        RenderTemplate('templates/stats_summary.html', values))

  def _DisplayBrokenClients(self):
    """Displays a report of broken clients."""
    # client with broken python
    py_computers = models.ComputerClientBroken.all().filter('fixed =', False)
    py_computers = list(py_computers)
    for computer in py_computers:
      computer.details = computer.details.replace("'", "\\'")
      computer.details = computer.details.replace('"', "\\'")
      computer.details = re.sub('\n', '<br/>', computer.details)
      computer.broken_datetimes.reverse()

    # clients with zero connection
    zero_conn_computers = models.Computer.AllActive().filter(
        'connections_on_corp =', 0).filter('connections_off_corp =', 0).fetch(
        COMPUTER_FETCH_LIMIT)
    zero_conn_computers = list(zero_conn_computers)
    zero_conn_computers.sort(key=lambda x: x.preflight_datetime, reverse=True)

    # clients with no recent postflight, but recent preflight
    # NOTE: this takes ~5s to complete in ~20k fleet where ~1400 clients have
    #       old postflight_datetime. if far more clients are in this state then
    #       then the query could cause DeadlineExceededError.
    pf_computers = []
    now = datetime.datetime.utcnow()
    not_recent = now - datetime.timedelta(days=15)
    q = models.Computer.AllActive().filter('postflight_datetime <', not_recent)
    for c in q:
      if not c.preflight_datetime or not c.postflight_datetime:
        continue  # already covered zero connection clients above.
      if (c.preflight_datetime - c.postflight_datetime).days > 7:
        pf_computers.append(c)
    pf_computers.sort(key=lambda x: x.preflight_datetime, reverse=True)

    self.response.out.write(RenderTemplate(
        'templates/stats_brokenclients.html',
        {'py_computers': py_computers,
         'zero_conn_computers': zero_conn_computers,
         'pf_computers': pf_computers}))

  def _DisplayMsuLogSummary(self, since_days=None):
    """Displays a summary of MSU logs."""
    key = 'msu_user_summary'
    if since_days:
      key = '%s_since_%sD_' % (key, since_days)
      human_since = '%s day(s)' % since_days
    else:
      human_since = 'forever'

    m = models.ReportsCache.get_by_key_name(key)
    summary = util.Deserialize(m.blob_value)
    summary_list = []
    keys = summary.keys()
    keys.sort(cmp=lambda x,y: cmp(summary[x], summary[y]))
    map(
        lambda x: summary_list.append({'var': x, 'val': summary[x]}),
        keys)

    self.response.out.write(RenderTemplate(
        'templates/stats_msulogsummary.html',
        {
            'summary': summary_list,
            'since': human_since,
            'mtime': m.mtime,
        }))

  def _DisplayMsuLogEvent(self):
    """Displays a summary of MSU logs."""
    event_name = self.request.get('event')
    query = models.ComputerMSULog.all().filter(
        'event =', event_name).order('-mtime')
    msu_events, next_page = self._Paginate(query, MSU_LOG_EVENT_LIMIT)
    self.response.out.write(RenderTemplate(
        'templates/stats_msulogsummary.html',
        {
            'msu_event_name': event_name,
            'msu_events': msu_events,
            'next_page': next_page,
            'limit': MSU_LOG_EVENT_LIMIT,
        }))

  def _DisplayHostManifest(self, uuid):
    """Display live manifest view for a host.

    Args:
      uuid: str, computer uuid to display
    """
    manifest = common.GetComputerManifest(uuid=uuid, packagemap=True)
    contents = manifest['plist'].GetContents()
    for itype in ['managed_installs', 'optional_installs', 'managed_updates']:
      for n in xrange(0, len(contents.get(itype, []))):
        if contents[itype][n] in manifest['packagemap']:
          contents[itype][n] = (
              '(((a href="'
              '/admin/installs?pkg=%s'
              '")))%s(((/a)))' % (
                  manifest['packagemap'][contents[itype][n]], contents[itype][n]
                  )
          )

    manifest_str = manifest['plist'].GetXml()
    manifest_str = manifest_str.replace('<', '&lt;')
    manifest_str = manifest_str.replace('>', '&gt;')
    manifest_str = manifest_str.replace('(((', '<')
    manifest_str = manifest_str.replace(')))', '>')

    self.response.out.write(RenderTemplate(
        'templates/stats_host_manifest.html',
        {
            'uuid': uuid,
            'manifest': manifest_str,
        }))

  def _DisplayUserSettings(self):
    """Displays a list of hosts with user_settings configured."""
    query = models.Computer.AllActive().filter('user_settings_exist =', True)
    computers, next_page = self._Paginate(query, USER_SETTINGS_FETCH_LIMIT)
    self.response.out.write(RenderTemplate(
        'templates/stats_user_settings.html',
        {'computers': computers}))

  def _DisplayAdminLogs(self):
    """Displays all models.AdminPackageLog entities."""
    query = models.AdminPackageLog.all().order('-mtime')
    logs, next_page = self._Paginate(query, ADMIN_LOG_FETCH_LIMIT)
    self.response.out.write(RenderTemplate(
        'templates/stats_adminlogs.html',
        {'logs': logs, 'limit': ADMIN_LOG_FETCH_LIMIT}))

  def _DisplayLostStolen(self):
    """Displays all models.ComputerLostStolen entities."""
    query = models.ComputerLostStolen.all().order('-mtime')
    computers, next_page = self._Paginate(query, COMPUTER_FETCH_LIMIT)
    self.response.out.write(RenderTemplate(
        'templates/stats_loststolen.html',
        {'computers': computers, 'limit': COMPUTER_FETCH_LIMIT}))

  def _DisplayPackageAlias(self):
    """Displays all models.PackageAlias entities."""
    query = models.PackageAlias.all().order('__key__')
    aliases, next_page = self._Paginate(query, COMPUTER_FETCH_LIMIT)
    self.response.out.write(RenderTemplate(
        'templates/stats_packagealias.html',
        {'aliases': aliases, 'limit': COMPUTER_FETCH_LIMIT}))


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