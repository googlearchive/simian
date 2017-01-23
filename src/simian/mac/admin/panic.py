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
"""Panic mode handler."""

import httplib

from google.appengine.api import users

from simian import settings
from simian.mac import admin
from simian.mac.common import mail
from simian.mac.munki import common


class AdminPanic(admin.AdminHandler):
  """Handler for /admin/panic."""

  def get(self):
    """GET handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return

    modes = []
    for mode in common.PANIC_MODES:
      d = {
          'name': mode,
          'enabled': common.IsPanicMode(mode),
      }
      modes.append(d)

    self.Render(
        'panic.html', {'modes': modes, 'report_type': 'panic'})

  @admin.AdminHandler.XsrfProtected('panic')
  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return

    mode = self.request.get('mode')
    enabled = self.request.get('enabled')
    verify = self.request.get('verify')

    if not verify:
      self.Render(
          'panic_set_verify.html',
          {'mode': {'name': mode, 'enabled': enabled}, 'report_type': 'panic'})
    else:
      if enabled == 'disable':
        enabled = False
      elif enabled == 'enable':
        enabled = True
      else:
        enabled = None

      if enabled is None:
        self.error(httplib.BAD_REQUEST)
      else:
        try:
          common.SetPanicMode(mode, enabled)

          user = users.get_current_user()
          subject = 'Panic Mode Update by %s' % user
          body = '%s has set \'%s\' for Panic Mode.\n' % (user, enabled)
          mail.SendMail(settings.EMAIL_ADMIN_LIST, subject, body)

          self.redirect('/admin/panic')
        except ValueError:
          self.error(httplib.BAD_REQUEST)
