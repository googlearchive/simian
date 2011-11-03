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
#

"""Apple Software Update Service Catalog URL handlers."""




import logging
import urllib
from google.appengine.ext import db
from google.appengine.ext import webapp
from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import gae_util
from simian.mac.munki import handlers
from simian.mac.munki import plist



class AppleSUS(handlers.AuthenticationHandler, webapp.RequestHandler):
  """Handler for /applesus/"""

  def get(self, client_id_str=''):
    """AppleSUS get handler.

    Args:
      name: str, optional, catalog name to get.
    """
    session = auth.DoAnyAuth()
    client_id = handlers.GetClientIdForRequest(
            self.request, session=session, client_id_str=client_id_str)

    # get only major.minor os_version, stripping miniscule versioning.
    # i.e. 10.6.6 becomes 10.6, 10.23.6.x.x becomes 10.23
    full_os_version = client_id.get('os_version', '') or ''
    os_version = '.'.join(full_os_version.split('.', 2)[:2])
    track = client_id.get('track', 'stable')
    catalog_name = '%s_%s' % (os_version, track)

    catalog = models.AppleSUSCatalog.MemcacheWrappedGet(catalog_name)
    if not catalog:
      logging.warning('Apple SUS catalog not found: %s', catalog_name)
      self.response.set_status(404)
      return

    header_date_str = self.request.headers.get('If-Modified-Since', '')
    catalog_date = catalog.mtime
    if handlers.IsClientResourceExpired(catalog_date, header_date_str):
      self.response.headers['Last-Modified'] = catalog_date.strftime(
          handlers.HEADER_DATE_FORMAT)
      self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
      self.response.out.write(catalog.plist)
    else:
      self.response.set_status(304)

  def put(self, name):
    """AppleSUS put handler.

    Args:
      name: str, catalog name to put.
    """
    gaeserver.DoMunkiAuth(require_level=gaeserver.LEVEL_UPLOADPKG)

    # try loading for validation's sake
    c = plist.AppleSoftwareCatalogPlist(self.request.body)
    try:
      c.Parse()
    except plist.PlistError, e:
      logging.exception('Invalid Apple SUS catalog format: %s', str(e))
      self.response.set_status(400)
      self.response.out.write(str(e))
      return
    del(c)

    lock = 'applesus_%s' % name
    if not gae_util.ObtainLock(lock, timeout=5.0):
      self.response.set_status(403)
      self.response.out.write('Could not lock applesus')
      return

    try:
      asucatalog = models.AppleSUSCatalog.get_or_insert(name)
      asucatalog.plist = self.request.body  # retain original appearance
      asucatalog.put()
    except (plist.PlistError, db.Error), e:
      logging.exception('applesus: %s', str(e))
      self.response.set_status(500)
      self.response.out.write(str(e))
      pass

    gae_util.ReleaseLock(lock)