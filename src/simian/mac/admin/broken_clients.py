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
"""Broken Clients admin handler."""


import re

from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth


# Number of preflight connections without a successful postflight before a
# is considered "broken."  1-2 is not a great number for various reasons;
# machines sleep/shutdown/drop network/etc. during Munki executions regularly.
PREFLIGHT_COUNT_BROKEN_THRESHOLD = 5


class BrokenClients(admin.AdminHandler):
  """Handler for /admin/brokenclients."""

  def get(self):
    """GET handler."""
    auth.DoUserAuth()
    self._DisplayBrokenClients()

  def post(self, uuid=None):
    """POST handler."""
    if not self.IsAdminUser() and not auth.IsSupportUser():
      self.response.set_status(403)
      return

    action = self.request.get('action')
    if action == 'set_fixed':
      uuid = self.request.get('uuid')
      c = models.ComputerClientBroken.get_by_key_name(uuid)
      if not c:
        self.response.out.write('UUID not found')
        return
      c.fixed = True
      c.put()

    self.redirect('/admin/brokenclients')

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
      computer.likely_fixed = False
      # if a UUID is set, attempt to figure out when it last connected.
      if computer.uuid:
        try:
          c_obj = models.Computer.get_by_key_name(computer.uuid)
          if c_obj.preflight_datetime > computer.broken_datetimes[0]:
            computer.likely_fixed = True
        except (IndexError, TypeError, models.db.Error):
          pass

    # clients with zero connection
    q = models.Computer.AllActive().filter(
        'connections_on_corp =', 0).filter('connections_off_corp =', 0).fetch(
            admin.DEFAULT_COMPUTER_FETCH_LIMIT)
    zero_conn_computers = []
    for c in q:
      if c.preflight_count_since_postflight > PREFLIGHT_COUNT_BROKEN_THRESHOLD:
        zero_conn_computers.append(c)
    zero_conn_computers.sort(key=lambda x: x.preflight_datetime, reverse=True)

    # clients with no recent postflight, but recent preflight
    fetch_limit = 1000
    pf_computers = []
    q = models.Computer.AllActive().filter(
        'preflight_count_since_postflight >', PREFLIGHT_COUNT_BROKEN_THRESHOLD)
    i = 0
    for c in q:
      i += 1
      if i >= fetch_limit:  # avoid DeadlineExceededError.
        break
      if not c.preflight_datetime or not c.postflight_datetime:
        continue  # already covered zero connection clients above.
      pf_computers.append(c)
    pf_computers.sort(key=lambda x: x.preflight_datetime, reverse=True)

    self.Render(
        'broken_clients.html',
        {'py_computers': py_computers,
         'zero_conn_computers': zero_conn_computers,
         'pf_computers': pf_computers,
         'is_security_user': auth.IsSecurityUser(),
         'report_type': 'broken_clients',
         'truncated': i >= fetch_limit,
         'preflight_count_broken_threshold': PREFLIGHT_COUNT_BROKEN_THRESHOLD,
        })
