#!/usr/bin/env python
# 
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""IP Blacklist admin handler."""





import re
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import util

IP_REGEX = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$'

class IPBlacklist(admin.AdminHandler):

  def get(self):
    """GET handler."""
    if not auth.IsAdminUser():
      self.error(403)
      return
    try:
      ips = util.Deserialize(
          models.KeyValueCache.MemcacheWrappedGet('client_exit_ip_blocks',
                                                  'text_value'))
    except util.DeserializeError:
      ips = []
      return
    d = {'report_type': 'ip_blacklist', 'list': ips, 'title': 'IP Blacklist',
         'regex': '/%s/' % IP_REGEX,
         'infopanel': 'Subnet format required (e.g. 192.168.1.0/24)'}
    self.Render('list_edit.html', d)

  def post(self):
    """POST handler."""
    if not auth.IsAdminUser():
      self.error(403)
      return
    values = self.request.get_all('item', None)
    ips = []
    is_ip = re.compile(IP_REGEX)
    for ip in values:
      if is_ip.match(ip):
        ips.append(ip)
      else:
        self.error(400)
        self.response.out.write('Malformed IP: "%s"' % ip)
        return
    models.KeyValueCache.MemcacheWrappedSet('client_exit_ip_blocks',
                                            'text_value',
                                            util.Serialize(ips))
    self.redirect('/admin/ip_blacklist?msg=IPs%20saved')