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
"""Host admin handler."""

import json

from google.appengine.api import users

from simian import settings
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import util


SINGLE_HOST_DATA_FETCH_LIMIT = 250


class Host(admin.AdminHandler):
  """Handler for /admin/host."""

  def get(self, uuid=None):
    """GET handler."""
    if uuid:
      uuid = util.UrlUnquote(uuid)
    else:
      self.response.set_status(404)
      return

    computer = models.Computer.get_by_key_name(uuid)
    if not computer:
      self.response.set_status(404)
      return

    self_report = bool(auth.DoUserAuthWithSelfReportFallback(
        constrain_username=computer.owner))

    self._DisplayHost(computer, self_report)

  def post(self, uuid=None):
    """POST handler."""
    if not self.IsAdminUser() and not auth.IsSupportUser():
      self.response.set_status(403)
      return

    action = self.request.get('action')

    if action == 'set_inactive':
      c = models.Computer.get_by_key_name(uuid)
      if not c:
        self.response.out.write('UUID not found')
        return
      c.active = False
      c.put(update_active=False)
      msg = 'Host set as inactive.'

    elif action == 'upload_logs':
      c = models.Computer.get_by_key_name(uuid)
      if not c:
        self.response.set_status(404)
        return
      c.upload_logs_and_notify = users.get_current_user().email()
      c.put()
      self.response.set_status(200)
      self.response.headers['Content-Type'] = 'application/json'
      self.response.out.write(
          json.dumps({'email': c.upload_logs_and_notify}))
      return

    else:
      self.response.set_status(400)
      return

    self.redirect('/admin/host/%s?msg=%s' % (uuid, msg))

  def _DisplayHost(self, computer, self_report):
    """Displays the report for a single host.

    Args:
      computer: models.Computer object to display.
      self_report: if True, display as self report.
    """

    uuid = computer.uuid

    popup = self.request.get('format', None) == 'popup'
    if popup:
      limit = 1
    else:
      limit = SINGLE_HOST_DATA_FETCH_LIMIT
    client_log_files = models.ClientLogFile.all().filter('uuid =', uuid).order(
        '-mtime').fetch(limit)
    msu_log = models.ComputerMSULog.all().filter('uuid =', uuid).order(
        '-mtime').fetch(limit)
    applesus_installs = models.InstallLog.all().filter('uuid =', uuid).filter(
        'applesus =', True).order('-mtime').fetch(limit)
    installs = models.InstallLog.all().filter('uuid =', uuid).filter(
        'applesus =', False).order('-mtime').fetch(limit)
    exits = models.PreflightExitLog.all().filter('uuid =', uuid).order(
        '-mtime').fetch(limit)
    install_problems = models.ClientLog.all().filter(
        'action =', 'install_problem').filter('uuid =', uuid).order(
            '-mtime').fetch(limit)

    tags = {}
    tags_list = []
    if computer:
      # Generate tags data.
      tags_list = models.Tag.GetAllTagNamesForEntity(computer)
      for tag in tags_list:
        tags[tag] = True
      for tag in models.Tag.GetAllTagNames():
        if tag not in tags:
          tags[tag] = False
      tags = json.dumps(tags, sort_keys=True)

      admin.AddTimezoneToComputerDatetimes(computer)
      computer.connection_dates.reverse()
      computer.connection_datetimes.reverse()

    try:
      uuid_lookup_url = settings.UUID_LOOKUP_URL
    except AttributeError:
      uuid_lookup_url = None

    try:
      owner_lookup_url = settings.OWNER_LOOKUP_URL
    except AttributeError:
      owner_lookup_url = None

    values = {
        'uuid_lookup_url': uuid_lookup_url,
        'owner_lookup_url': owner_lookup_url,
        'client_site_enabled': settings.CLIENT_SITE_ENABLED,
        'computer': computer,
        'applesus_installs': applesus_installs,
        'installs': installs,
        'client_log_files': client_log_files,
        'msu_log': msu_log,
        'install_problems': install_problems,
        'preflight_exits': exits,
        'tags': tags,
        'tags_list': tags_list,
        'host_report': True,
        'limit': SINGLE_HOST_DATA_FETCH_LIMIT,
        'is_support_user': auth.IsSupportUser(),
        'is_security_user': auth.IsSecurityUser(),
        'is_physical_security_user': auth.IsPhysicalSecurityUser(),
        'self_report': self_report
    }

    if popup:
      self.Render('host_popup.html', values)
    else:
      self.Render('host.html', values)
