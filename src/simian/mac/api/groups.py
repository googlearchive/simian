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
"""Groups API URL handlers."""

import httplib
import json
import logging


import webapp2

from simian import settings
from simian.mac import models
from simian.mac.common import auth

API_INFO_KEY = settings.API_INFO_KEY


class GroupHandler(webapp2.RequestHandler):
  """Handler for /api/groups/."""

  def __init__(self, *args, **kwargs):
    self.user = None
    super(GroupHandler, self).__init__(*args, **kwargs)

  def _DoAuth(self):
    try:
      self.user = auth.DoOAuthAuth()
    except auth.NotAuthenticated:
      enable_admin_check = True
      # OAuth was either not used or failed, so perform regular user auth.
      self.user = auth.DoUserAuth(is_admin=enable_admin_check)

  def _CheckApiKey(self):
    key = self.request.headers.get('X-Simian-API-Info-Key')

    if not API_INFO_KEY:
      logging.warning('API_INFO_KEY is unset; blocking all API info requests.')
      self.response.abort(httplib.UNAUTHORIZED)
    elif key != API_INFO_KEY:
      self.response.abort(httplib.UNAUTHORIZED)

  def get(self):
    """List groups, or list a group's memberhsip.

    Send optional 'group' parameter to list membership of a specified group.
    Otherwise a list of groups is returned.
    """
    self._CheckApiKey()

    self.response.headers['Content-Type'] = 'application/json'

    group = self.request.get('group')
    if group:
      existing_group = models.Group.get_by_key_name(group)
      if existing_group:
        self.response.out.write(json.dumps(existing_group.users))
    else:
      self.response.out.write(json.dumps(models.Group.GetAllGroupNames()))

  def post(self):
    """Create a new group, or overwrites an existing group's membership list."""
    self._DoAuth()
    self._CheckApiKey()

    group = self.request.get('group')
    members = list(set(self.request.get('members').split(',')))

    new_group = models.Group(key_name=group, users=members)
    new_group.put()

  def put(self):
    """Creates a new group, or extends existing group's membership."""
    self._DoAuth()
    self._CheckApiKey()

    group = self.request.get('group')
    members = self.request.get('members').split(',')

    existing_group = models.Group.get_by_key_name(group)
    if existing_group:
      existing_group.users.extend(members)
      existing_group.users = list(set(existing_group.users))
      existing_group.put()
    else:
      self.post()

  def delete(self, group=None):
    """Delete an entire group."""
    self._DoAuth()
    self._CheckApiKey()

    if group:
      existing_group = models.Group.get_by_key_name(group)
      if existing_group:
        existing_group.delete()
