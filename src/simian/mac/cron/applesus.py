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

"""Module containing url handler for all Apple Updates related crons.

Classes:
  AppleSUSCatalogSync: syncs SUS catalogs from Apple.
"""




import datetime
import logging
import os
import urllib2
from google.appengine.api import mail
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.runtime import apiproxy_errors
from simian import settings
from simian.mac import common
from simian.mac import models
from simian.mac.common import applesus
from simian.mac.munki import plist


# TODO(user): move this map to a Datastore model.
# NOTE: Since these are HTTP retrievals, we are trusting the App Engine prod
#       network to not be hijacked and return malicious catalogs.
CATALOGS = {
    '10.5': 'http://swscan.apple.com/content/catalogs/others/index-leopard.merged-1.sucatalog.gz',
    '10.6': 'http://swscan.apple.com/content/catalogs/others/index-leopard-snowleopard.merged-1.sucatalog.gz',
    '10.7': 'http://swscan.apple.com/content/catalogs/others/index-lion-snowleopard-leopard.merged-1.sucatalog.gz',
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
      logging.info('_UpdateCatalog: %s update complete.', entity.key().name())
    except db.Error:
      logging.exception('AppleSUSCatalogSync._UpdateCatalog() db.Error.')
      raise

  def _NotifyAdminsOfCatalogSync(
      self, catalog, new_products, deprecated_products):
    """Notifies Simian admins that a new Apple Updates catalog was synced.

    Args:
      catalog: models.AppleSUSCatalog entity.
      new_products: a list of models.AppleSUSProduct objects.
      deprecated_products: a list of models.AppleSUSProduct objects.
    """
    new_products = ['%s: %s %s' % (p.product_id, p.name, p.version)
                    for p in new_products]
    deprecated_products = ['%s: %s %s' % (p.product_id, p.name, p.version)
                           for p in deprecated_products]
    if not new_products and not deprecated_products:
      return  # don't notify if the new catalog has no product changes.
    catalog_name = catalog.key().name()
    m = mail.EmailMessage()
    m.to = [settings.EMAIL_ADMIN_LIST]
    m.sender = settings.EMAIL_SENDER
    m.subject = '%s Apple Updates catalog synced to Simian.' % catalog_name
    new_msg = '\n\nNew Products:\n%s' % '\n'.join(new_products)
    if deprecated_products:
      dep_msg = '\n\nDeprecated Products:\n%s' % '\n'.join(deprecated_products)
    else:
      dep_msg = ''
    m.body = '%s Apple Updates catalog synced to Simian on %s UTC.%s%s' % (
        catalog_name, catalog.mtime, new_msg, dep_msg)
    try:
      m.send()
    except apiproxy_errors.DeadlineExceededError:
      #logging.info('Email failed to send; skipping.')
      pass

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
      #logging.info(
      #    '%s SUS catalog is old. Updating...', catalog.key().name())
      header_date_str = response.headers.get('Last-Modified', '')
      self._UpdateCatalog(xml, entity=catalog, last_modified=header_date_str)
      return True
    else:
      raise urlfetch.DownloadError(
         'Non-200 status_code: %s' % response.status_code)

  def _UpdateProductDataFromCatalog(self, catalog_plist):
    """Updates models.AppleSUSProduct model from a catalog plist object.

    Args:
      catalog_plist: plist.ApplePlist object.

    Returns:
      list of new models.AppleSUSProduct objects, or empty list.
    """
    if not 'Products' in catalog_plist:
      logging.error('Products not found in Apple Updates catalog')
      return []

    new_products = []

    # Create a dict of all previously processed product IDs for fast lookup.
    existing_products = {}
    products_query = models.AppleSUSProduct.all()
    for product in products_query:
      existing_products[product.product_id] = True

    # Loop over all products IDs in the Apple Updates catalog, adding any new
    # products to the models.AppleSUSProduct model.
    catalog_product_keys = catalog_plist.get('Products', {}).keys()
    catalog_product_keys.sort()
    for key in catalog_product_keys:
      if key in existing_products:
        continue  # This product has already been processed in the past.

      #logging.debug('Processing new product: %s', key)

      distributions = catalog_plist['Products'][key]['Distributions']
      url = distributions.get('English', None) or distributions.get('en', None)
      if not url:
        logging.error(
            'No english distributions exists for product %s; skipping.', key)
        continue  # No english distribution exists :(

      r = urllib2.urlopen(url)
      if r.code != 200:
        #logging.warning('Skipping dist where HTTP status != 200')
        continue
      dist_str = r.read()
      dist = applesus.ParseDist(dist_str)

      product = models.AppleSUSProduct(key_name=key)
      product.product_id = key
      product.name = dist['title']
      product.apple_mtime = catalog_plist['Products'][key]['PostDate']
      product.version = dist['version']
      product.description = dist['description']
      product.tracks = [common.UNSTABLE]
      product.put()
      new_products.append(product)

      #logging.debug('Product complete: %s', product.name)

    return new_products

  def _DeprecateOrphanedProducts(self):
    """Deprecates products in Datastore that no longer exist in any catalogs.

    Returns:
      List of AppleSUSProduct objects that were marked deprecated.
    """
    # Loop over all catalogs, generating a dict of all unique product ids.
    catalog_products = {}
    for catalog in CATALOGS:
      for track in common.TRACKS + ['untouched']:
        key = '%s_%s' % (catalog, track)
        catalog_obj = models.AppleSUSCatalog.get_by_key_name(key)
        if not catalog_obj:
          logging.error('Catalog does not exist: %s', key)
          continue
        catalog_plist = plist.ApplePlist(catalog_obj.plist)
        try:
          catalog_plist.Parse()
        except plist.Error:
          logging.exception('Error parsing Apple Updates catalog plist: %s', key)
          continue
        for product in catalog_plist.get('Products', []):
          catalog_products[product] = 1

    deprecated = []
    # Loop over Datastore products, deprecating any that aren't in any catalogs.
    for p in models.AppleSUSProduct.all().filter('deprecated =', False):
      if p.product_id not in catalog_products:
        p.deprecated = True
        p.put()
        deprecated.append(p)
    return deprecated

  def _ProcessCatalogAndNotifyAdmins(self, catalog, os_version):
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

    new_products = self._UpdateProductDataFromCatalog(catalog_plist)
    deprecated_products = self._DeprecateOrphanedProducts()

    self._NotifyAdminsOfCatalogSync(catalog, new_products, deprecated_products)

    # Regenerate the unstable catalog, including new updates but excluding
    # any that were previously manually disabled.
    applesus.GenerateAppleSUSCatalog(os_version, common.UNSTABLE)

  def get(self):
    """Handle GET"""
    for os_version, url in CATALOGS.iteritems():
      untouched_key = '%s_untouched' % os_version
      untouched_catalog = models.AppleSUSCatalog.get_or_insert(untouched_key)
      #logging.debug('Downloading %s catalog...', untouched_key)
      if self._UpdateCatalogIfChanged(untouched_catalog, url):
        self._ProcessCatalogAndNotifyAdmins(untouched_catalog, os_version)
      else:
        #logging.info('%s SUS catalog has NOT changed.', os_version)
        pass


class AppleSUSAutoPromote(webapp.RequestHandler):
  """Class to auto-promote Apple Updates."""

  def _NotifyAdminsOfAutoPromotions(self, promotions):
    """Notifies Simian admins that a new Apple Updates were auto-promoted.

    Args:
      promotions: a dict of track keys with lists of update product entities.
    """
    m = mail.EmailMessage()
    m.to = [settings.EMAIL_ADMIN_LIST]
    m.sender = settings.EMAIL_SENDER
    m.subject = 'Apple Updates Auto-Promotion'
    msg = []
    for track, updates in promotions.iteritems():
      msg.append('\n%s:' % track)
      for u in updates:
        msg.append('\t%s: %s %s' % (u.product_id, u.name, u.version))
    msg = '\n'.join(msg)
    m.body = 'The following Apple Updates were promoted:\n%s' % msg
    try:
      m.send()
    except apiproxy_errors.DeadlineExceededError:
      #logging.info('Email failed to send; skipping.')
      pass

  def _ReadyToAutoPromote(self, applesus_product, track):
    """Returns boolean whether AppleSUSProduct should be promoted or not.

    Args:
      applesus_product: models.AppleSUSProduct object.
      track: str track like testing or stable.
    Returns:
      Boolean. True if the product is ready to promote, False otherwise.
    """
    today = datetime.datetime.utcnow().date()
    auto_promote_date =  applesus.GetAutoPromoteDate(track, applesus_product)
    if auto_promote_date and auto_promote_date <= today:
      return True
    return False

  def get(self):
    """Auto-promote updates that have been on a previous track for N days."""
    promotions = {}
    for track in [common.TESTING, common.STABLE]:
      for p in models.AppleSUSProduct.all().filter('tracks !=', track):
        if track in p.tracks:
          continue  # Datastore indexes may not be up to date...
        if not self._ReadyToAutoPromote(p, track):
          continue

        logging.info(
            'AppleSUSProduct being promoted to %s: %s %s',
            track, p.product_id, p.name)
        p.tracks.append(track)
        p.put()

        log = models.AdminAppleSUSProductLog(
            product_id=p.product_id,
            action='auto-promote to %s' % track,
            tracks=p.tracks)
        log.put()

        if track not in promotions:
          promotions[track] = []
        promotions[track].append(p)

      if track in promotions:
        applesus.GenerateAppleSUSCatalogs(track)

    if promotions:
      self._NotifyAdminsOfAutoPromotions(promotions)