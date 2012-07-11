#!/usr/bin/env python
# 
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Apple SUS admin handler."""



import calendar
import logging
import os
from google.appengine.api import users
from simian import settings
from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import applesus
from simian.mac.common import auth
from simian.mac.common import util


DEFAULT_APPLESUS_LOG_FETCH = 25


class AppleSUSAdmin(admin.AdminHandler):
  """Handler for /admin/applesus."""

  def post(self, report=None, product_id=None):
    """POST handler."""
    #logging.debug('POST called: report=%s, product_id=%s', report, product_id)
    if not auth.IsAdminUser():
      self.response.set_status(403)
      return

    if report == 'product' and product_id:
      self._ChangeProduct(product_id)
    elif self.request.get('regenerate-catalogs'):
      self._RegenerateCatalogs()
    else:
      self.response.set_status(404)

  def _RegenerateCatalogs(self):
    """Regenerates specified Apple SUS catalogs."""
    tracks = self.request.get_all('tracks')
    #logging.info('Admin requested catalog regeneration for tracks: %s', tracks)
    if tracks:
      applesus.GenerateAppleSUSCatalogs(tracks=tracks, delay=1)
      self.redirect('/admin/applesus?msg=Catalog regeneration in progress.')

  def _ChangeProduct(self, product_id):
    """Method to change properties of a given Apple SUS product."""
    user = users.get_current_user()

    track = self.request.get('track')
    enabled = self.request.get('enabled', None)
    manual_override = self.request.get('manual_override', None)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    if not product:
      #logging.warning('POST to unknown applesus product_id: %s', product_id)
      self.response.set_status(404)
      return

    log_args = {}
    data = {
        'product_id': product_id,
    }

    # set/unset manual_override property
    if manual_override is not None:
      manual_override = bool(int(manual_override))
      product.manual_override = manual_override
      product.put()
      #logging.info(
      #    'Manual override on Apple SUS %s: %s',
      #    product_id, manual_override)
      log_action = 'manual_override=%s' % manual_override
      for track in common.TRACKS:
        if track not in product.tracks:
           prom_date = applesus.GetAutoPromoteDate(track, product)
           if prom_date:
             data['%s_promote_date' % track] = prom_date.strftime('%b. %d, %Y')
      data['manual_override'] = manual_override
    # add/remove track to product
    elif enabled is not None:
      enabled = bool(int(enabled))
      if enabled:
        if track not in product.tracks:
          #logging.info('Adding %s to Apple SUS %s catalog', product_id, track)
          product.tracks.append(track)
          product.put()
      else:
        if track in product.tracks:
          #logging.info(
          #    'Removing %s from Apple SUS %s catalog', product_id, track)
          product.tracks.remove(track)
          product.put()
      log_action = '%s=%s' % (track, enabled)
      data.update({'track': track, 'enabled': enabled})

    log = models.AdminAppleSUSProductLog(
        product_id=product_id,
        action=log_action,
        tracks=product.tracks,
        user=user.email())
    log.put()

    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(util.Serialize(data))

    # TODO(user): the above should utilize the App Engine Channel API to
    # notify clients of such changes, refreshing the products for any admin
    # viewing this page.

  def get(self, report=None, product_id=None):
    """GET handler."""
    auth.DoUserAuth()
    if not report:
      self._DisplayMain()
    if report == 'product':
      self._DisplayProductDescription(product_id)
    elif report == 'logs':
      self._DisplayUpdateLog()
    else:
      self.response.set_status(404)

  def _DisplayMain(self):
    query = models.AppleSUSProduct.all().filter(
        'deprecated =', False).order('-apple_mtime')
    products = []
    # NOTE(user): the following adds about 700ms onto the request, so we may
    #             want to pre-calculate this in a cron in the future.
    for p in query:
      if common.STABLE not in p.tracks:
        p.stable_promote_date = applesus.GetAutoPromoteDate(common.STABLE, p)
      if common.TESTING not in p.tracks:
        p.testing_promote_date = applesus.GetAutoPromoteDate(common.TESTING, p)
      products.append(p)

    catalogs = []
    for os_version in applesus.OS_VERSIONS:
      c = models.AppleSUSCatalog.MemcacheWrappedGet('%s_untouched' % os_version)
      if c:
        catalogs.append({'version': os_version, 'download_datetime': c.mtime})

    data = {
        'catalogs': catalogs,
        'products': products,
        'tracks': common.TRACKS,
        'auto_promote_enabled': settings.APPLE_AUTO_PROMOTE_ENABLED,
        'auto_promote_stable_weekday': calendar.day_name[
            settings.APPLE_AUTO_PROMOTE_STABLE_WEEKDAY],
        'unstable_grace_period_days': settings.APPLE_UNSTABLE_GRACE_PERIOD_DAYS,
        'testing_grace_period_days': settings.APPLE_TESTING_GRACE_PERIOD_DAYS,
        'report_type': 'apple_applesus'
    }
    self.Render('applesus_list.html', data)

  def _DisplayProductDescription(self, product):
    product = models.AppleSUSProduct.get_by_key_name(product)
    self.response.out.write(product.description)

  def _DisplayUpdateLog(self):
    logs = models.AdminAppleSUSProductLog.all().order('-mtime')
    values = {
        'logs': self.Paginate(logs, DEFAULT_APPLESUS_LOG_FETCH),
        'report_type': 'apple_logs',
    }
    self.Render('applesus_log.html', values)