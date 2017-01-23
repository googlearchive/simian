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
"""Groups admin handler."""

import httplib
import urllib

from simian.mac import admin
from simian.mac import models


class Groups(admin.AdminHandler):
  """Handler for /admin/groups."""

  def get(self):
    """GET handler."""
    groups = models.Group.all()
    groups = sorted(groups, key=lambda t: unicode.lower(t.key().name()))
    d = {'groups': groups, 'can_mod_groups': self.IsAdminUser(),
         'report_type': 'groups'}
    self.Render('groups.html', d)

  @admin.AdminHandler.XsrfProtected('groups')
  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return

    group_name = urllib.unquote(self.request.get('group').strip())
    action = self.request.get('action')
    if action == 'create':
      group = models.Group(key_name=group_name)
      users = self.request.get_all('user')
      if users:
        group.users = users
      group.put()
      msg = 'Group successfully saved.'
    elif action == 'delete':
      group_manifest_mods = models.GroupManifestModification.all().filter(
          'group_key_name =', group_name).get()
      if group_manifest_mods:
        msg = "Group not deleted as it's being used for Manifest Modifications."
      else:
        group = models.Group.get_by_key_name(group_name)
        if group:
          group.delete()
        else:
          self.error(httplib.NOT_FOUND)
          return
        msg = 'Group successfully deleted.'
    elif action == 'change':
      users = self.request.get_all('user')
      add_group = self.request.get('add') == '1'
      group = models.Group.get_by_key_name(group_name)
      if not group:
        self.error(httplib.NOT_FOUND)
        return

      if add_group:
        group.users += users
      else:
        group.users = [u for u in group.users if u not in users]
      group.put()
      msg = 'Group successfully modified.'

    self.redirect('/admin/groups?msg=%s' % msg)
