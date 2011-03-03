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

"""Module containing url handler for all Apple SUS related crons.

Classes:
  AppleSUSCatalogSync: syncs SUS catalogs from Apple.
"""




import logging
import os
from google.appengine.api import mail
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.runtime import apiproxy_errors
from google.appengine.ext.webapp.util import run_wsgi_app
from simian import settings
from simian.mac import models


# TODO(user): move this map to a Datastore model.
# NOTE: Since these are HTTP retrievals, we are trusting the App Engine prod
#       network to not be hijacked and return malicious catalogs.
CATALOGS = {
    '10.5': 'http://swscan.apple.com/content/catalogs/others/index-leopard.merged-1.sucatalog',
    '10.6': 'http://swscan.apple.com/content/catalogs/others/index-leopard-snowleopard.merged-1.sucatalog',
}


class AppleSUSCatalogSync(webapp.RequestHandler):
  """Class to sync SUS catalogs from Apple."""

  def _UpdateCatalog(self, plist, key=None, entity=None, last_modified=None):
    """Updates a Datastore entry.

    Args:
      plist: str xml catalog plist.
      key: key of AppleSUSCatalog entity to update.
        or
      entity: AppleSUSCatalog entity to update.
      last_modified: str Last-Modified header datetime.
    """
    if not key and not entity:
      raise ValueError('either key OR entity is required.')

    try:
      if not entity:
        entity = models.AppleSUSCatalog.get_or_insert(key)
      entity.plist = plist
      entity.last_modified_header = last_modified
      entity.put()
      logging.info('%s update complete.', entity.key().name())
    except db.Error:
      logging.exception('AppleSUSCatalogSync._UpdateCatalog() db.Error.')
      raise

  def _NotifyAdminsOfCatalogSync(self, catalog):
    """Notifies Simian admins that a new Apple SUS catalog was synced.

    Args:
      catalog: models.AppleSUSCatalog entity.
    """
    catalog_name = catalog.key().name()
    m = mail.EmailMessage()
    m.to = settings.ADMINS
    m.sender = settings.EMAIL_SENDER
    m.subject = '%s Apple SUS catalog synced to Simian.' % catalog_name
    m.body = '%s Apple SUS catalog synced to Simian on %s UTC.' % (
        catalog_name, catalog.mtime)
    try:
      m.send()
    except apiproxy_errors.DeadlineExceededError:
      logging.info('Email failed to send; skipping.')

  def _UpdateCatalogIfChanged(self, catalog, url):
    """Returns the contents of a url passed to URLFetch.fetch().

    Args:
      catalog: models.AppleSUSCatalog entity to update.
      url: str url to fetch.
    Returns:
      Boolean. True if the catalog was updated, False otherwise.
    Raises:
      urlfetch.Error on failures.
    """
    headers = {'If-Modified-Since': catalog.last_modified_header}
    response = urlfetch.fetch(url, headers=headers, deadline=30)
    if response.status_code == 304:
      return False
    elif response.status_code == 200:
      xml = response.content
      # TODO(user): validate response plist here.
      logging.info(
          '%s SUS catalog is old. Updating...', catalog.key().name())
      header_date_str = response.headers.get('Last-Modified', '')
      self._UpdateCatalog(xml, entity=catalog, last_modified=header_date_str)
      return True
    else:
      raise urlfetch.DownloadError(
         'Non-200 status_code: %s' % response.status_code)

  def get(self):
    """Handle GET"""
    for os_version, url in CATALOGS.iteritems():
      untouched_key = '%s_untouched' % os_version
      untouched_catalog = models.AppleSUSCatalog.get_or_insert(untouched_key)
      logging.debug('Downloading %s catalog...')
      if self._UpdateCatalogIfChanged(untouched_catalog, url):
        # TODO(user): instead of directly updating unstable, fire off the
        # future filtering engine that generates the unstable catalog.
        self._UpdateCatalog(
            untouched_catalog.plist, key='%s_unstable' % os_version)

        self._NotifyAdminsOfCatalogSync(untouched_catalog)
      else:
        logging.info('%s SUS catalog has NOT changed.', os_version)


application = webapp.WSGIApplication([
    (r'/cron/applesus/catalogsync$', AppleSUSCatalogSync),
])


def main():
  if os.environ.get('SERVER_SOFTWARE', '').startswith('Development'):
    logging.getLogger().setLevel(logging.DEBUG)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()