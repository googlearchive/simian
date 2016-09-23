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
"""Catalogs URL handlers."""
import httplib

from simian.mac import models
from simian.mac.common import auth
from simian.mac.munki import handlers


class Catalogs(handlers.AuthenticationHandler):
  """Handler for /catalogs/"""

  def get(self, name):
    """Catalog get handler.

    Args:
      name: string catalog name to get.

    Returns:
      A webapp.Response() response.
    """
    auth.DoAnyAuth()

    catalog = models.Catalog.MemcacheWrappedGet(name)
    if not catalog:
      self.response.set_status(httplib.NOT_FOUND)
      return

    header_date_str = self.request.headers.get('If-Modified-Since', '')
    if not handlers.IsClientResourceExpired(catalog.mtime, header_date_str):
      self.response.set_status(httplib.NOT_MODIFIED)
      return

    self.response.headers['Last-Modified'] = catalog.mtime.strftime(
        handlers.HEADER_DATE_FORMAT)

    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(catalog.plist_xml)
