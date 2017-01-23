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
"""Admin handler."""

import httplib
import urllib

from simian.mac import admin
from simian.mac import models
from simian.mac.admin import maintenance
from simian.mac.common import auth
from simian.mac.common import util
from simian.mac.munki import common


DEFAULT_USER_SETTINGS_FETCH_LIMIT = 200
DEFAULT_ADMIN_LOG_FETCH_LIMIT = 25
DEFAULT_INSTALL_LOG_FETCH_LIMIT = 25
DEFAULT_PREFLIGHT_EXIT_LOG_FETCH_LIMIT = 25
DEFAULT_MSU_LOG_EVENT_LIMIT = 25


class Misc(admin.AdminHandler):
  """"Handler for /admin."""

  XSRF_PROTECTION = False

  def get(self, report=None, uuid=None):
    """Misc get handler."""
    auth.DoUserAuth()
    if report == 'hostmanifest':
      self._DisplayHostManifest(uuid=uuid)
    elif report == 'installs':
      pending = self.request.get('pending') == '1'
      pkg = urllib.unquote(self.request.get('pkg', 'all'))
      if pending:
        self._DisplayHostsPendingPkg(pkg)
      else:
        self._DisplayInstallsForPackage(pkg)
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
    elif report == 'manifest':
      track = uuid
      self._DisplayManifest(track)
    elif report == 'msulogsummary':
      self._DisplayMsuLogSummary()
    elif report == 'msulogevent':
      self._DisplayMsuLogEvent()
    elif report == 'user_settings':
      self._DisplayUserSettings()
    elif report == 'clientlog':
      log_key_name = uuid
      l = models.ClientLogFile.get_by_key_name(log_key_name)
      if l:
        self.response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        self.response.out.write(l.log_file)
      else:
        self.response.out.write('Log not found')
        self.response.set_status(httplib.NOT_FOUND)
    elif report == 'maintenance':
      if not self.IsAdminUser():
        self.response.set_status(httplib.FORBIDDEN)
        return
      # TODO(user): move into separate handler
      action = uuid
      if action == 'update_installs_schema':
        maintenance.UpdateInstallLogSchema()
      elif action == 'rebuild_install_counts':
        maintenance.RebuildInstallCounts()
      else:
        self.response.set_status(httplib.NOT_FOUND)
    else:
      self.response.set_status(httplib.NOT_FOUND)

  def _DisplayInstallsForPackage(self, pkg):
    """Displays a list of installs of a particular package."""
    applesus = self.request.get('applesus') == '1'
    failures = self.request.get('failures') == '1'

    query = models.InstallLog.all()

    if failures:
      query.filter('success =', False)
    else:
      query.filter('success =', True)

    if pkg == 'all':
      query.filter('applesus =', applesus)
    else:
      query.filter('package =', pkg)

    query.order('-mtime')

    installs = self.Paginate(query, DEFAULT_INSTALL_LOG_FETCH_LIMIT)

    values = {'pkg': pkg, 'applesus': applesus, 'failures': failures}
    if applesus:
      values['applesus_installs'] = installs
      values['report_type'] = (
          failures and 'apple_failures' or 'apple_installs')
      self.Render('applesus_installs.html', values)
    else:
      values['installs'] = installs
      values['report_type'] = (
          failures and 'packages_failures' or 'packages_installs')
      self.Render('installs.html', values)

  def _DisplayHostsPendingPkg(self, pkg):
    """Displays a list of hosts where pkg is pending installation."""
    query = models.Computer.AllActive().filter(
        'pkgs_to_install =', pkg).order('-preflight_datetime')
    computers = self.Paginate(query, admin.DEFAULT_COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'pkg': pkg, 'cached': False,
              'report_type': 'pkgs_to_install'}
    self.Render('summary.html', values)

  def _DisplayInstallProblems(self):
    """Displays all installation problems."""
    query = models.ClientLog.all().filter('action =', 'install_problem').order(
        '-mtime')
    problems = self.Paginate(query, DEFAULT_INSTALL_LOG_FETCH_LIMIT)
    values = {'install_problems': problems, 'report_type': 'packages_problems'}
    self.Render('install_problems.html', values)

  def _DisplayPreflightExits(self):
    """Displays all preflight exits."""
    query = models.PreflightExitLog.all().order('-mtime')
    exits = self.Paginate(query, DEFAULT_PREFLIGHT_EXIT_LOG_FETCH_LIMIT)
    values = {'preflight_exits': exits, 'report_type': 'preflight_exits'}
    self.Render('preflight_exits.html', values)

  def _DisplayLowDiskFree(self):
    """Displays a report of machines with lowest disk space."""
    query = models.Computer.AllActive().order('root_disk_free')
    computers = self.Paginate(query, admin.DEFAULT_COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'diskfree',
              'cached': False}
    self.Render('summary.html', values)

  def _DisplayLongestUptime(self):
    """Displays a report of machines with longest uptime."""
    query = models.Computer.AllActive().order('-uptime')
    computers = self.Paginate(query, admin.DEFAULT_COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'uptime', 'cached': False}
    self.Render('summary.html', values)

  def _DisplayLongestOffCorp(self):
    """Displays a report of machines with longest off corp time."""
    query = models.Computer.AllActive().order('last_on_corp_preflight_datetime')
    computers = self.Paginate(query, admin.DEFAULT_COMPUTER_FETCH_LIMIT)
    values = {'computers': computers, 'report_type': 'offcorp', 'cached': False}
    self.Render('summary.html', values)

  def _DisplayManifest(self, track):
    """Displays Manifests in a template."""
    m = models.Manifest.get_by_key_name(track)
    self.Render('plist.html',
                {'plist_type': 'manifests',
                 'xml': admin.XmlToHtml(m.plist.GetXml()),
                 'title': track + ' manifest',
                 'report_type': 'manifest_%s' % track,
                 'raw_xml_link': '/manifests/track=' + track,
                })

  def _DisplayMsuLogSummary(self):
    """Displays a summary of MSU logs."""
    summaries = []
    for since_days in None, 7, 1:
      key = 'msu_user_summary'
      if since_days:
        key = '%s_since_%sD_' % (key, since_days)
        human_since = '%s day(s)' % since_days
      else:
        human_since = 'forever'

      m = models.ReportsCache.get_by_key_name(key)
      if not m or not m.blob_value:
        continue
      summary = util.Deserialize(m.blob_value)
      summary_list = []
      keys = summary.keys()
      keys.sort(cmp=lambda x, y: cmp(summary[x], summary[y]), reverse=True)
      for x in keys:
        summary_list.append({'var': x, 'val': summary[x]})

      summaries.append(
          {'values': summary_list, 'since': human_since, 'mtime': m.mtime})

    # TODO(user): Since the above is a list now, memcache here.

    self.Render(
        'msu_log_summary.html',
        {'summaries': summaries, 'report_type': 'msu_gui_logs'})

  def _DisplayMsuLogEvent(self):
    """Displays a summary of MSU logs."""
    event_name = self.request.get('event')
    query = models.ComputerMSULog.all().filter(
        'event =', event_name).order('-mtime')
    msu_events = self.Paginate(query, DEFAULT_MSU_LOG_EVENT_LIMIT)
    values = {'msu_event_name': event_name, 'msu_events': msu_events}
    self.Render('msu_log_summary.html', values)

  def _DisplayHostManifest(self, uuid):
    """Display live manifest view for a host.

    Args:
      uuid: str, computer uuid to display
    """
    if not uuid:
      self.response.set_status(httplib.NOT_FOUND)
      return
    manifest = common.GetComputerManifest(uuid=uuid, packagemap=True)
    manifest_str = manifest['plist'].GetXml()

    if self.request.get('format') == 'xml':
      self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
      self.response.out.write(manifest_str)
    else:
      manifest_html = admin.XmlToHtml(manifest_str)
      self.Render(
          'plist.html',
          {'plist_type': 'host_manifest',
           'title': 'Host Manifest: %s' % uuid,
           'xml': manifest_html,
           'raw_xml_link': '/admin/hostmanifest/%s?format=xml' % uuid})

  def _DisplayUserSettings(self):
    """Displays a list of hosts with user_settings configured."""
    query = models.Computer.AllActive().filter('user_settings_exist =', True)
    computers = self.Paginate(query, DEFAULT_USER_SETTINGS_FETCH_LIMIT)
    self.Render(
        'user_settings.html',
        {'computers': computers, 'report_type': 'usersettings_knobs'})
