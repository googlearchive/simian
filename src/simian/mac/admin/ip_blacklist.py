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
"""IP Blacklist admin handler."""

import httplib
import re
from simian.mac import admin
from simian.mac import models
from simian.mac.common import util

IP_REGEX = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$'


class IPBlacklist(admin.AdminHandler):

  def get(self):
    """GET handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return
    ips = {}
    try:
      ips = util.Deserialize(
          models.KeyValueCache.MemcacheWrappedGet('client_exit_ip_blocks',
                                                  'text_value'))
    except util.DeserializeError:
      pass
    d = {'report_type': 'ip_blacklist', 'title': 'IP Blacklist', 'columns': 2,
         'list': sorted(ips.items()), 'labels': ['IP', 'Comment'],
         'regex': ['/%s/' % IP_REGEX, '/^.{0,60}$/'],
         'infopanel': 'Subnet format required (e.g. 192.168.1.0/24)'}
    self.Render('list_edit.html', d)

  @admin.AdminHandler.XsrfProtected('ip_blacklist')
  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return
    values = self.request.get_all('item_0', None)
    comments = self.request.get_all('item_1', None)
    if values and (not comments or len(values) != len(comments)):
      self.error(httplib.BAD_REQUEST)
      return
    is_ip = re.compile(IP_REGEX)
    if not all(map(is_ip.match, values)):
      self.error(httplib.BAD_REQUEST)
      self.response.out.write('Malformed IP')
      return
    ips = dict(zip(values, comments))
    models.KeyValueCache.MemcacheWrappedSet('client_exit_ip_blocks',
                                            'text_value',
                                            util.Serialize(ips))
    self.redirect('/admin/ip_blacklist?msg=IPs%20saved')
