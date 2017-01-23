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
"""Packages admin handler."""

import datetime
import httplib

from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import auth


DEFAULT_PACKAGE_LOG_FETCH_LIMIT = 25


class Packages(admin.AdminHandler):
  """Handler for /admin/packages."""

  DATASTORE_MODEL = models.PackageInfo
  LOGGING_MODEL = models.AdminPackageLog
  TEMPLATE = 'packages.html'
  REPORT_TYPE = 'packages'
  LOG_REPORT_TYPE = 'package_logs'

  def get(self, report=None):
    """GET handler."""
    auth.DoUserAuth()

    if report == 'logs':
      self._DisplayLogs()
    else:
      historical = self.request.get('historical') == '1'
      applesus = self.request.get('applesus') == '1'
      if historical or applesus:
        self._DisplayPackagesListFromCache(applesus=applesus)
      else:
        self._DisplayPackagesList()

  def _GetPackageQuery(self):
    """Build query."""
    all_packages = self.request.get('all_packages') == '1'
    query = self.DATASTORE_MODEL.all()
    if self.REPORT_TYPE == 'packages' and not all_packages:
      query.filter('catalogs IN', common.TRACKS)
    return query

  def _DisplayPackagesList(self):
    """Displays list of all installs/removals/etc."""
    installs, counts_mtime = models.ReportsCache.GetInstallCounts()
    pending, pending_mtime = models.ReportsCache.GetPendingCounts()
    packages = []
    all_packages = self.request.get('all_packages') == '1'
    query = self._GetPackageQuery()
    for p in query:
      if not p.plist:
        self.error(httplib.FORBIDDEN)
        self.response.out.write('Package %s has a broken plist!' % p.filename)
        return
      pkg = {}
      pkg['count'] = installs.get(p.munki_name, {}).get('install_count', 'N/A')
      pkg['fail_count'] = installs.get(p.munki_name, {}).get(
          'install_fail_count', 'N/A')
      pkg['pending_count'] = pending.get(p.munki_name, 'N/A')
      pkg['duration_seconds_avg'] = installs.get(p.munki_name, {}).get(
          'duration_seconds_avg', None) or 'N/A'
      pkg['unattended'] = p.plist.get('unattended_install', False)
      pkg['unattended_uninstall'] = p.plist.get('unattended_uninstall', False)
      force_install_after_date = p.plist.get('force_install_after_date', None)
      if force_install_after_date:
        pkg['force_install_after_date'] = force_install_after_date
      pkg['catalogs'] = p.catalog_matrix
      pkg['manifests'] = p.manifest_matrix
      pkg['munki_name'] = p.munki_name or p.plist.GetMunkiName()
      pkg['filename'] = p.filename
      pkg['file_size'] = p.plist.get('installer_item_size', 0) * 1024
      pkg['install_types'] = p.install_types
      pkg['manifest_mod_access'] = p.manifest_mod_access
      pkg['description'] = p.description
      packages.append(pkg)

    packages.sort(key=lambda pkg: pkg['munki_name'].lower())

    self.Render(self.TEMPLATE,
                {'packages': packages, 'counts_mtime': counts_mtime,
                 'pending_mtime': pending_mtime,
                 'report_type': self.REPORT_TYPE,
                 'active_pkg': self.request.GET.get('activepkg'),
                 'is_support_user': auth.IsSupportUser(),
                 'can_upload': auth.HasPermission(auth.UPLOAD),
                 'is_admin': auth.IsAdminUser(),
                 'all_packages': all_packages,})

  def _DisplayPackagesListFromCache(self, applesus=False):
    installs, counts_mtime = models.ReportsCache.GetInstallCounts()
    pkgs = []
    names = installs.keys()
    names.sort()
    for name in names:
      install = installs[name]
      if applesus and install.get('applesus', False):
        d = {'name': name,
             'count': install.get('install_count', 'N/A'),
             'fail_count': install.get('install_fail_count', 'N/A'),
             'duration_seconds_avg': install.get('duration_seconds_avg', 'N/A')}
        pkgs.append(d)
      elif not applesus and not install['applesus']:
        d = {'name': name,
             'count': install.get('install_count', 'N/A'),
             'fail_count': install.get('install_fail_count', 'N/A'),
             'duration_seconds_avg': install.get('duration_seconds_avg', 'N/A')}
        pkgs.append(d)
    if applesus:
      report_type = 'apple_historical'
    else:
      report_type = 'packages_historical'
    self.Render(
        self.TEMPLATE,
        {'packages': pkgs, 'counts_mtime': counts_mtime,
         'applesus': applesus, 'cached_pkgs_list': True,
         'report_type': report_type})

  def _DisplayLogs(self):
    """Displays all models.AdminPackageLog entities."""
    key_id = self.request.get('plist')
    if key_id:
      try:
        key_id = int(key_id)
      except ValueError:
        self.error(httplib.NOT_FOUND)
        return
      log = self.LOGGING_MODEL.get_by_id(key_id)
      if self.request.get('format') == 'xml':
        self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
        self.response.out.write(log.plist)
      else:
        time = datetime.datetime.strftime(log.mtime, '%Y-%m-%d %H:%M:%S')
        title = 'plist for Package Log <b>%s - %s</b>' % (log.filename, time)
        raw_xml = '/admin/packages/logs?plist=%d&format=xml' % key_id
        self.Render(
            'plist.html',
            {'plist_type': 'package_log',
             'xml': admin.XmlToHtml(log.plist.GetXml()),
             'title': title,
             'raw_xml_link': raw_xml,
            })
    else:
      filename = self.request.get('filename')
      query = self.LOGGING_MODEL.all()
      if filename:
        query.filter('filename =', filename)
      query.order('-mtime')
      logs = self.Paginate(query, DEFAULT_PACKAGE_LOG_FETCH_LIMIT)
      formatted_logs = []
      for log in logs:
        formatted_log = {}
        formatted_log['data'] = log
        if (hasattr(log, 'proposed_catalogs')
            and hasattr(log, 'proposed_manifest')):
          formatted_log['catalogs'] = common.util.MakeTrackMatrix(
              log.catalogs, log.proposed_catalogs)
          formatted_log['manifests'] = common.util.MakeTrackMatrix(
              log.manifests, log.proposed_manifests)
        else:
          formatted_log['catalogs'] = common.util.MakeTrackMatrix(log.catalogs)
          formatted_log['manifests'] = common.util.MakeTrackMatrix(
              log.manifests)
        formatted_logs.append(formatted_log)
      self.Render(
          'package_logs.html',
          {'logs': formatted_logs,
           'report_type': self.LOG_REPORT_TYPE,
           'filename': filename})


class PackageProposals(Packages):
  """Handler for /admin/proposals."""

  DATASTORE_MODEL = models.PackageInfoProposal
  LOGGING_MODEL = models.AdminPackageProposalLog
  TEMPLATE = 'packages.html'
  LOG_REPORT_TYPE = 'proposal_logs'
  REPORT_TYPE = 'proposals'

  def _GetPackageQuery(self):
    return self.DATASTORE_MODEL.all()
