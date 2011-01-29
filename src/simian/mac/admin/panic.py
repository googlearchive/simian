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





import os
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from simian import settings
from simian.mac.munki import common


class AdminPanic(webapp.RequestHandler):
  """Handler for /admin/panic."""

  def IsAdmin(self):
    """Returns True if the user is an admin."""
    user = users.get_current_user()
    return user is not None and user.email() in settings.ADMINS

  def get(self):
    """GET handler."""
    if not self.IsAdmin():
      return

    modes = []
    for mode in common.PANIC_MODES:
      d = {
        'name': mode,
        'enabled': common.IsPanicMode(mode),
      }
      modes.append(d)

    path = os.path.join(
        os.path.dirname(__file__), 'templates/panic.html')
    html = template.render(path, {'modes': modes})
    self.response.out.write(html)

  def post(self):
    """POST handler."""
    if not self.IsAdmin():
      return

    mode = self.request.get('mode')
    enabled = self.request.get('enabled')
    verify = self.request.get('verify')

    if not verify:
      path = os.path.join(
          os.path.dirname(__file__), 'templates/panic_set_verify.html')
      html = template.render(path,
          {'mode': {'name': mode, 'enabled': enabled}})
      self.response.out.write(html)
    else:
      if enabled == 'disable':
        enabled = False
      elif enabled == 'enable':
        enabled = True
      else:
        enabled = None

      if enabled is None:
        self.error(400)
      else:
        try:
          common.SetPanicMode(mode, enabled)
          self.redirect('/admin/panic')
        except ValueError:
          self.error(400)