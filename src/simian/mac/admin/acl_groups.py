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
"""ACL Groups admin handler."""

import re
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import util

# TODO(user): consolidate email regex duplicated in settings.
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b'


class ACLGroups(admin.AdminHandler):

  def get(self, group=None):
    """GET handler."""
    if not self.IsAdminUser():
      self.error(403)
      return

    if group:
      group_members = self.GetMembers(group)
      d = {'report_type': 'acl_groups', 'list': [(gm,) for gm in group_members],
           'columns': 1, 'regex': [r'/%s/' % MAIL_REGEX],
           'title': 'ACL Group: %s' % group, 'back': '/admin/acl_groups',
           'infopanel': 'Full email address required (e.g. user@example.com)'}
      self.Render('list_edit.html', d)
    else:
      group_data = []
      for name, title in auth.ACL_GROUPS.items():
        members = self.GetMembers(name)
        group_data.append({'name': name, 'title': title, 'members': members})
      d = {'report_type': 'acl_groups', 'groups': group_data}
      self.Render('acl_groups.html', d)

  def post(self, group=None):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(403)
      return

    if group:
      values = self.request.get_all('item_0', None)
      members = []
      is_email = re.compile(MAIL_REGEX)
      for member in values:
        if is_email.match(member):
          members.append(member)
        else:
          self.error(400)
          self.response.out.write('malformed email')
          return
      models.KeyValueCache.MemcacheWrappedSet(group, 'text_value',
                                              util.Serialize(members))
      self.redirect('/admin/acl_groups?msg=Group%20saved')

  def GetMembers(self, group_name):
    """Get a list of members belonging to the group."""
    members = models.KeyValueCache.MemcacheWrappedGet(group_name, 'text_value')
    member_list = []
    if members:
      try:
        member_list = util.Deserialize(members)
      except util.DeserializeError:
        pass
    return member_list
