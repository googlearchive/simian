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
"""Generates 'Managed Software Update Update' text for MSU releases."""

import datetime
import httplib

import distutils.version

from google.appengine.api import users

from simian import settings
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth

OSX_VERSIONS = {
    # TODO(user): We should only maintain one set of system versions.
    '6': 'Snow Leopard (MacOS X 10.6)',
    '7': 'Lion (OS X 10.7)',
    '8': 'Mountain Lion (OS X 10.8)',
    '9': 'Mavericks (OS X 10.9)',
    '10': 'Yosemite (OS X 10.10)',
    '11': 'El Capitan (OS X 10.11)',
    '12': 'Sierra (macOS 10.12)',
}


def GetOSXMajorVersion(os):
  if os:
    version = distutils.version.LooseVersion(os).version
    if len(version) < 2:
      return None
    return str(version[1])
  return None


class ReleaseReport(admin.AdminHandler):
  """Handler for /admin/release_report."""

  XSRF_PROTECTION = False

  def get(self):
    """GET handler."""
    auth.DoUserAuth()
    self._DisplayReleaseReport()

  def post(self, date=None, range_of_days=None):
    """POST handler."""
    auth.DoUserAuth()
    if date:
      if range_of_days:
        self._DisplayReleaseReport(date, range_of_days)
      else:
        self._DisplayReleaseReport(date)
    else:
      self._DisplayReleaseReport()

  def _DisplayReleaseReport(self, date=None, range_of_days=6):
    """Displays Managed Software Update Update report."""
    # TODO(user): This should probably handle subversions of the OS as well.
    # TODO(user): This should be able to do a testing report as well.
    try:
      period = datetime.timedelta(days=range_of_days)
    except TypeError:
      self.error(httplib.BAD_REQUEST)
      self.response.out.write('invalid date input')
      return
    candidate_items = []
    if not date:
      start_date = datetime.datetime.utcnow()
    else:
      try:
        start_date = datetime.datetime(date)
      except TypeError:
        self.error(httplib.BAD_REQUEST)
        self.response.out.write('invalid date input')
        return
    # Get all package logs for the appropriate time range.
    query = models.AdminPackageLog.all()
    query.filter('mtime >', start_date - period)
    # Check for packages that were in stable in some log entry.
    for item in query:
      if 'stable' in item.catalogs:
        if item.filename not in candidate_items:
          candidate_items.append(item.filename)
    # Pass list of packages that were in stable in the time range.
    final_list = self.ItemQualificationCheck(
        candidate_items, start_date, range_of_days)
    # Generate Actual Report.
    final_report, contains_forced_install = self.MakeReleaseReport(final_list)
    username = users.get_current_user()
    report_date = str(datetime.date.today())
    self.Render('release_report.html', {
        'report_items': final_report,
        'admin_username': username,
        'contains_forced_install': contains_forced_install,
        'report_date': report_date,
        'salutation': settings.RELEASE_REPORT_SALUTATION,
        'title': settings.RELEASE_REPORT_TITLE,
        'subject_line_flag': settings.RELEASE_REPORT_SUBJECT_FLAG,
        'introduction': settings.RELEASE_REPORT_INTRODUCTION,
        'introduction_warning': settings.RELEASE_REPORT_INTRODUCTION_WARNING,
        'managed_install_text': settings.RELEASE_REPORT_MANAGED_INSTALL_TEXT,
        'managed_update_and_optional_text':
            settings.RELEASE_REPORT_MANAGED_UPDATE_AND_OPTIONAL_TEXT,
        'managed_update_text': settings.RELEASE_REPORT_MANAGED_UPDATE_TEXT,
        'optional_install_text': settings.RELEASE_REPORT_OPTIONAL_INSTALL_TEXT,
        'unattended_and_forced_text':
            settings.RELEASE_REPORT_UNATTENDED_AND_FORCED_TEXT,
        'forced_text': settings.RELEASE_REPORT_FORCED_TEXT,
        'restart_required_text': settings.RELEASE_REPORT_RESTART_REQUIRED_TEXT,
        'signature': settings.RELEASE_REPORT_SIGNATURE,
        'version_verb': settings.RELEASE_REPORT_VERSION_VERB,
        })

  def MakeReleaseReport(self, filename_list):
    """Generates Release Report report as a dict."""
    report = []
    contains_forced_install = False
    for filename in filename_list:
      message_dict = self.Message(filename)
      report.append(message_dict)
      if message_dict['is_forced_install']:
        contains_forced_install = True
    return report, contains_forced_install

  def ItemQualificationCheck(self, filename_list, date, range_of_days):
    """Checks to see if packages were promoted to stable within date range."""
    result_set = set([])
    period = datetime.timedelta(days=range_of_days)
    for filename in filename_list:
      p = models.PackageInfo.get_by_key_name(filename)
      # Package must currently be in stable to be considered.
      if p:
        if 'stable' in p.catalogs and 'stable' in p.manifests:
          query = query = models.AdminPackageLog.all()
          query.filter('filename =', filename)
          query.order('-mtime')
          # iterates over log entries in reverse chronological order.
          for item in query:
            # If it was not in stable in the next log entry it makes the list.
            if 'stable' not in item.catalogs:
              result_set.add(item.filename)
              break
            # If it was in stable prior to the date range, it does not.
            else:
              if item.mtime < date - period:
                break
    return result_set

  def InstallOsTextGenerator(self, min_os=None, max_os=None):
    """Generates readable text about minimum and maximum OSs for a package.

    Args:
      min_os: Minimum OS setting as a string.
      max_os: Maximum OS setting as a string.

    Returns:
      result: String, which OSs will get the install.
    """
    # TODO(user): This should handle minor releases as well.
    # If a minimum or maximum OS is set, this reads only the 4th character,
    # which will correspond with the major OS version.
    min_os_major = GetOSXMajorVersion(min_os)
    if min_os_major == '4' or min_os_major == '5':
      min_os_major = None

    max_os_major = GetOSXMajorVersion(max_os)
    if max_os_major or min_os_major:
      if max_os_major == min_os_major:
        result_string = ' %s %s.' % (settings.RELEASE_REPORT_VERSION_VERB,
                                     OSX_VERSIONS[max_os_major])
      elif max_os_major and not min_os_major:
        result_string = ' %s %s and earlier versions of the OS.' % (
            settings.RELEASE_REPORT_VERSION_VERB, OSX_VERSIONS[max_os_major])
      elif min_os_major and not max_os_major:
        result_string = ' %s %s and later versions of the OS.' % (
            settings.RELEASE_REPORT_VERSION_VERB, OSX_VERSIONS[min_os_major])
      else:
        version_list = []
        for version_number in range(int(min_os_major), int(max_os_major)+1):
          version_list.append(OSX_VERSIONS[str(version_number)])
        and_list = ' and '.join(version_list)
        grammar_string = and_list.replace(' and ', ', ', len(version_list)-2)
        result_string = ' %s %s.' % (settings.RELEASE_REPORT_VERSION_VERB,
                                     grammar_string)
    else:
      result_string = '.'
    return result_string

  def Message(self, filename):
    """Generates list of items with report parameters."""
    item_dict = {}
    p = models.PackageInfo.get_by_key_name(filename)

    if p.plist.get('display_name', None):
      item_dict['package_name'] = p.plist.get('display_name', '')
    else:
      item_dict['package_name'] = p.plist.get('name', '')

    minimum_os_version = p.plist.get('minimum_os_version', None)
    maximum_os_version = p.plist.get('maximum_os_version', None)
    item_dict['osx_version_string'] = self.InstallOsTextGenerator(
        minimum_os_version, maximum_os_version)
    install_types = set(p.install_types)
    if 'managed_installs' in install_types:
      item_dict['managed_install'] = True
    else:
      item_dict['managed_install'] = False
    if 'optional_installs' in install_types:
      item_dict['optional_install'] = True
    else:
      item_dict['optional_install'] = False
    if 'managed_updates' in install_types:
      item_dict['managed_update'] = True
    else:
      item_dict['managed_update'] = False

    item_dict['is_unattended'] = p.plist.get('unattended_install', False)
    item_dict['is_unattended_uninstall'] = p.plist.get(
        'unattended_uninstall', False)

    if p.plist.get('force_install_after_date', None):
      force_date_raw = p.plist.get('force_install_after_date', None)
      item_dict['forced_on_date'] = force_date_raw.strftime('%B %d')
      item_dict['is_forced_install'] = True
    else:
      item_dict['is_forced_install'] = False

    if p.plist.get('RestartAction', None) == 'RequireRestart':
      item_dict['restart_required'] = True
    else:
      item_dict['restart_required'] = False

    item_dict['version'] = p.plist['version']
    return item_dict
