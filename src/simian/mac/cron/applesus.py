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
"""Module containing url handler for all Apple Updates related crons.

Classes:
  AppleSUSCatalogSync: syncs SUS catalogs from Apple.
"""

import datetime
import gc
import httplib
import logging
import time
import urllib2
import webapp2

from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext import deferred

from simian import settings
from simian.mac import common
from simian.mac import models
from simian.mac.common import applesus
from simian.mac.common import mail
from simian.mac.munki import plist


# TODO(user): move this map to a Datastore model.
# Note: The unit test applesus_test enforces the existence and format of this
# variable.
CATALOGS = {
    '10.6': ('https://swscan.apple.com/content/catalogs/others/'
             'index-leopard-snowleopard.merged-1.sucatalog.gz'),
    '10.7': ('https://swscan.apple.com/content/catalogs/others/'
             'index-lion-snowleopard-leopard.merged-1.sucatalog.gz'),
    '10.8': ('https://swscan.apple.com/content/catalogs/others/'
             'index-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog'),
    '10.9': ('https://swscan.apple.com/content/catalogs/others/'
             'index-10.9-mountainlion-lion-snowleopard-leopard.'
             'merged-1.sucatalog'),
    '10.10': ('https://swscan.apple.com/content/catalogs/others/'
              'index-10.10-10.9-mountainlion-lion-snowleopard-leopard.'
              'merged-1.sucatalog'),
    '10.11': ('https://swscan.apple.com/content/catalogs/others/'
              'index-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.'
              'merged-1.sucatalog'),
    '10.12': ('https://swscan.apple.com/content/catalogs/others/'
              'index-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-'
              'leopard.merged-1.sucatalog')
}

RESTART_REQUIRED_FOOTER = '* denotes restart required'


class AppleSUSCatalogSync(webapp2.RequestHandler):
  """Class to sync SUS catalogs from Apple."""

  @classmethod
  def _UpdateCatalog(
      cls, plist_str, key=None, entity=None, last_modified=None):
    """Updates a Datastore entry.

    Args:
      plist_str: str xml catalog plist.
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
      entity.plist = plist_str
      entity.last_modified_header = last_modified
      entity.put()
      logging.info('_UpdateCatalog: %s update complete.', entity.key().name())
    except db.Error:
      logging.exception('AppleSUSCatalogSync._UpdateCatalog() db.Error.')
      raise

  @classmethod
  def _NotifyAdminsOfCatalogSync(
      cls, catalog, new_products, deprecated_products):
    """Notifies Simian admins that a new Apple Updates catalog was synced.

    Args:
      catalog: models.AppleSUSCatalog entity.
      new_products: a list of models.AppleSUSProduct objects.
      deprecated_products: a list of models.AppleSUSProduct objects.
    """
    if not new_products and not deprecated_products:
      return  # don't notify if the new catalog has no product changes.
    new_products_strs = [
        '%s: %s %s %s' % (
            p.product_id, p.name, p.version, '*' if p.restart_required else '')
        for p in new_products]
    deprecated_products_strs = ['%s: %s %s' % (p.product_id, p.name, p.version)
                                for p in deprecated_products]
    catalog_name = catalog.key().name()

    new_msg = '\n\nNew Products:\n%s' % '\n'.join(new_products_strs)
    if deprecated_products_strs:
      dep_msg = '\n\nDeprecated Products:\n%s' % '\n'.join(
          deprecated_products_strs)
    else:
      dep_msg = ''
    if any(p.restart_required for p in new_products):
      restart_note = '\n\n%s' % RESTART_REQUIRED_FOOTER
    else:
      restart_note = ''
    body = '%s Apple Updates catalog synced to Simian on %s UTC.%s%s%s' % (
        catalog_name, catalog.mtime, new_msg, dep_msg, restart_note)
    subject = '%s Apple Updates catalog synced to Simian.' % catalog_name

    mail.SendMail([settings.EMAIL_ADMIN_LIST], subject, body)

  @classmethod
  def _UpdateCatalogIfChanged(cls, catalog, url):
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
    response = urlfetch.fetch(
        url, headers=headers, deadline=30, validate_certificate=True)
    if response.status_code == httplib.NOT_MODIFIED:
      return False
    elif response.status_code == httplib.OK:
      xml = response.content
      # TODO(user): validate response plist here.
      #logging.info(
      #    '%s SUS catalog is old. Updating...', catalog.key().name())
      header_date_str = response.headers.get('Last-Modified', '')
      cls._UpdateCatalog(xml, entity=catalog, last_modified=header_date_str)
      return True
    else:
      raise urlfetch.DownloadError(
          'Non-200 status_code: %s' % response.status_code)

  @classmethod
  def _UpdateProductDataFromCatalog(cls, catalog_plist):
    """Updates models.AppleSUSProduct model from a catalog plist object.

    Args:
      catalog_plist: plist.ApplePlist object.

    Returns:
      list of new models.AppleSUSProduct objects, or empty list.
    """
    if 'Products' not in catalog_plist:
      logging.error('Products not found in Apple Updates catalog')
      return []

    new_products = []

    # Create a dict of all previously processed product IDs for fast lookup.
    existing_products = set()
    products_query = models.AppleSUSProduct.all().filter('deprecated =', False)
    for product in products_query:
      existing_products.add(product.product_id)

    # Loop over all products IDs in the Apple Updates catalog, adding any new
    # products to the models.AppleSUSProduct model.
    catalog_product_keys = catalog_plist.get('Products', {}).keys()
    catalog_product_keys.sort()
    for key in catalog_product_keys:
      if key in existing_products:
        continue  # This product has already been processed in the past.

      # Download and parse distribution metadata.
      distributions = catalog_plist['Products'][key]['Distributions']
      dist_url = distributions.get(
          'English', None) or distributions.get('en', None)
      if not dist_url:
        logging.error(
            'No english distributions exists for product %s; skipping.', key)
        continue  # No english distribution exists :(
      r = urllib2.urlopen(dist_url)
      if r.code != httplib.OK:
        continue
      dist_str = r.read()
      dist = applesus.DistFileDocument()
      dist.LoadDocument(dist_str)

      product = models.AppleSUSProduct(key_name=key)
      product.product_id = key
      product.name = dist.title
      product.apple_mtime = catalog_plist['Products'][key]['PostDate']
      product.version = dist.version
      product.description = dist.description
      product.tracks = [common.UNSTABLE]
      product.restart_required = dist.restart_required
      if not dist.restart_required and settings.APPLE_AUTO_UNATTENDED_ENABLED:
        product.unattended = True
      else:
        product.unattended = False

      # Parse package download URLs.
      for package in catalog_plist['Products'][key]['Packages']:
        product.package_urls.append(package.get('URL'))

      product.put()
      new_products.append(product)

    return new_products

  @classmethod
  def _DeprecateOrphanedProducts(cls):
    """Deprecates products in Datastore that no longer exist in any catalogs.

    Returns:
      List of AppleSUSProduct objects that were marked deprecated.
    """
    # Loop over all catalogs, generating a dict of all unique product ids.
    catalog_products = set()
    for os_version in applesus.OS_VERSIONS:
      for track in common.TRACKS + ['untouched']:
        key = '%s_%s' % (os_version, track)
        catalog_obj = models.AppleSUSCatalog.get_by_key_name(key)
        if not catalog_obj:
          logging.error('Catalog does not exist: %s', key)
          continue
        catalog_plist = plist.ApplePlist(catalog_obj.plist)
        try:
          catalog_plist.Parse()
        except plist.Error:
          logging.exception('Error parsing Apple Updates catalog: %s', key)
          continue
        for product in catalog_plist.get('Products', []):
          catalog_products.add(product)
      # catalog xml is ~4MB, parsing creates a lot of interconnected
      # temporary objects
      gc.collect()

    deprecated = []
    # Loop over Datastore products, deprecating all that aren't in any catalogs.
    for p in models.AppleSUSProduct.all().filter('deprecated =', False):
      if p.product_id not in catalog_products:
        p.deprecated = True
        p.put()
        deprecated.append(p)
    return deprecated

  @classmethod
  def _ProcessCatalogAndNotifyAdmins(cls, catalog, os_version):
    """Wrapper method to process a catalog and notify admin of changes.

    Args:
      catalog: models.AppleSUSCatalog object to process.
      os_version: str OS version like 10.5, 10.6, 10.7, etc.
    """
    catalog_plist = plist.ApplePlist(catalog.plist)
    try:
      catalog_plist.Parse()
    except plist.Error:
      logging.exception(
          'Error parsing Apple Updates catalog: %s', catalog.key().name())
      return

    new_products = cls._UpdateProductDataFromCatalog(catalog_plist)
    deprecated_products = cls._DeprecateOrphanedProducts()

    cls._NotifyAdminsOfCatalogSync(catalog, new_products, deprecated_products)

    # Regenerate the unstable catalog, including new updates but excluding
    # any that were previously manually disabled.
    applesus.GenerateAppleSUSCatalog(os_version, common.UNSTABLE)

    models.AdminAppleSUSProductLog.Log(
        new_products, 'new for %s' % os_version)
    models.AdminAppleSUSProductLog.Log(
        deprecated_products, 'deprecated for %s' % os_version)

  @classmethod
  def _ProcessCatalog(cls, os_version):
    url = CATALOGS.get(os_version, 'UNKNOWN_OS_VERSION')
    untouched_key = '%s_untouched' % os_version
    untouched_catalog = models.AppleSUSCatalog.get_or_insert(untouched_key)
    try:
      if cls._UpdateCatalogIfChanged(untouched_catalog, url):
        cls._ProcessCatalogAndNotifyAdmins(untouched_catalog, os_version)
    except (urlfetch.DownloadError, urlfetch.InvalidURLError):
      logging.exception(
          'Unable to download Software Update catalog for %s', os_version)

  def get(self):
    """Handle GET."""
    for os_version in applesus.OS_VERSIONS:
      deferred_name = 'applesus_catalog_sync_%s_%d' % (
          os_version.replace('.', '-'), int(time.time()))
      deferred.defer(
          self._ProcessCatalog, os_version, _name=deferred_name,
          _queue='serial')


class AppleSUSAutoPromote(webapp2.RequestHandler):
  """Class to auto-promote Apple Updates."""

  def _NotifyAdminsOfAutoPromotions(self, promotions):
    """Notifies Simian admins that a new Apple Updates were auto-promoted.

    Args:
      promotions: a dict of track keys with lists of update product entities.
    """
    msg = []
    restart_required = False
    for track, updates in promotions.iteritems():
      msg.append('\n%s:' % track)
      for u in updates:
        msg.append('\t%s: %s %s %s' % (
            u.product_id, u.name, u.version, '*' if u.restart_required else ''))
        if u.restart_required:
          restart_required = True
    if restart_required:
      msg.append('\n\n%s' % RESTART_REQUIRED_FOOTER)
    msg = '\n'.join(msg)
    body = 'The following Apple Updates were promoted:\n%s' % msg
    subject = 'Apple Updates Auto-Promotion'

    mail.SendMail([settings.EMAIL_ADMIN_LIST], subject, body)

  def _ReadyToAutoPromote(self, applesus_product, track, now=None):
    """Returns boolean whether AppleSUSProduct should be promoted or not.

    Args:
      applesus_product: models.AppleSUSProduct object.
      track: str track like testing or stable.
      now: datetime.datetime, optional, supply an alternative
           value for the current date/time.
    Returns:
      Boolean. True if the product is ready to promote, False otherwise.
    """
    now = now or datetime.datetime.utcnow()
    today = now.date()
    hour = now.strftime('%H')
    auto_promote_date = applesus.GetAutoPromoteDate(track, applesus_product)
    if auto_promote_date and auto_promote_date <= today:
      if settings.HOUR_START <= int(hour) <= settings.HOUR_STOP:
        return True
    return False

  def get(self, now=None):
    """Auto-promote updates that have been on a previous track for N days."""
    promotions = {}
    for track in [common.TESTING, common.STABLE]:
      for p in models.AppleSUSProduct.all().filter('tracks !=', track):
        if track in p.tracks:
          continue  # Datastore indexes may not be up to date...
        if not self._ReadyToAutoPromote(p, track, now):
          continue

        logging.info(
            'AppleSUSProduct being promoted to %s: %s %s',
            track, p.product_id, p.name)
        p.tracks.append(track)
        p.put()

        if track not in promotions:
          promotions[track] = []
        promotions[track].append(p)

      if track in promotions:
        applesus.GenerateAppleSUSCatalogs(track)
        models.AdminAppleSUSProductLog.Log(
            promotions[track], 'auto-promote to %s' % track)

    if promotions:
      self._NotifyAdminsOfAutoPromotions(promotions)
