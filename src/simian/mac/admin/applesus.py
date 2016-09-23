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
"""Apple SUS admin handler."""

import calendar
import datetime
import httplib
import json

from google.appengine.api import users
from google.appengine.ext import deferred

from simian import settings
from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import applesus
from simian.mac.common import auth
from simian.mac.common import gae_util

# pylint: disable=g-import-not-at-top
try:
  from simian.mac.common import mail
except ImportError:
  mail = None
# pylint: enable=g-import-not-at-top


DEFAULT_APPLESUS_LOG_FETCH = 25


class AppleSUSAdmin(admin.AdminHandler):
  """Handler for /admin/applesus."""

  @admin.AdminHandler.XsrfProtected('apple_applesus')
  def post(self, report=None, product_id=None):
    """POST handler."""
    if not self.IsAdminUser():
      self.response.set_status(httplib.FORBIDDEN)
      return

    if report == 'product' and product_id:
      self._ChangeProduct(product_id)
    elif self.request.get('regenerate-catalogs'):
      self._RegenerateCatalogs()
    else:
      self.response.set_status(httplib.NOT_FOUND)

  def _RegenerateCatalogs(self):
    """Regenerates specified Apple SUS catalogs."""
    tracks = self.request.get_all('tracks')
    if tracks:
      applesus.GenerateAppleSUSCatalogs(tracks=tracks, delay=1)
      self.redirect('/admin/applesus?msg=Catalog regeneration in progress.')
    else:
      self.redirect('/admin/applesus?msg=Select at least one catalog!')

  def _ChangeProduct(self, product_id):
    """Method to change properties of a given Apple SUS product."""
    user = users.get_current_user()

    track = self.request.get('track')
    enabled = self.request.get('enabled', None)
    manual_override = self.request.get('manual_override', None)
    unattended = self.request.get('unattended', None)
    force_install_after_date = self.request.get(
        'force_install_after_date', None)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    if not product:
      self.response.set_status(httplib.NOT_FOUND)
      return

    data = {
        'product_id': product_id,
    }

    changed_tracks = set()

    # set/unset manual_override property
    if manual_override is not None:
      manual_override = bool(int(manual_override))
      product.manual_override = manual_override
      product.put()
      log_action = 'manual_override=%s' % manual_override
      for track in common.TRACKS:
        if track not in product.tracks:
          prom_date = applesus.GetAutoPromoteDate(track, product)
          if prom_date:
            data['%s_promote_date' % track] = prom_date.strftime('%b. %d, %Y')
      data['manual_override'] = manual_override
    # set/unset force_install_after_date property
    elif force_install_after_date is not None:
      if force_install_after_date:
        try:
          tomorrow = datetime.datetime.utcnow() + datetime.timedelta(hours=12)
          if datetime.datetime.strptime(  # only allow future force install date
              force_install_after_date, '%Y-%m-%d %H:%M') > tomorrow:
            product.force_install_after_date_str = force_install_after_date
          else:
            self.error(httplib.BAD_REQUEST)
            return
        except ValueError:
          self.error(httplib.BAD_REQUEST)
          return
      else:
        product.force_install_after_date = None
      product.put()
      data['force_install_after_date'] = force_install_after_date
      log_action = 'force_install_after_date=%s' % force_install_after_date
      changed_tracks.update(product.tracks)
    # set/unset unattended property
    elif unattended is not None:
      unattended = bool(int(unattended))
      product.unattended = unattended
      product.put()
      data['unattended'] = unattended
      log_action = 'unattended=%s' % unattended
      changed_tracks.update(product.tracks)
    # add/remove track to product
    elif enabled is not None:
      enabled = bool(int(enabled))
      if enabled:
        if track not in product.tracks:
          product.tracks.append(track)
          product.put()
      else:
        if track in product.tracks:
          product.tracks.remove(track)
          product.put()
      log_action = '%s=%s' % (track, enabled)
      data.update({'track': track, 'enabled': enabled})
      changed_tracks.add(track)

    log = models.AdminAppleSUSProductLog(
        product_id=product_id,
        action=log_action,
        tracks=product.tracks,
        user=user.email())
    log.put()

    # Send email notification to admins
    if mail and settings.EMAIL_ON_EVERY_CHANGE:
      display_name = '%s - %s' % (product.name, product.version)

      subject = 'Apple SUS Update by %s - %s (%s)' % (
          user, display_name, product_id)
      body = '%s has set \'%s\' on %s.\n' % (
          user, log_action, display_name)
      body += '%s is now in %s track(s).\n' % (
          product_id, ', '.join(map(str, product.tracks)))
      mail.SendMail(settings.EMAIL_ADMIN_LIST, subject, body)

    # Regenerate catalogs for any changed tracks, if a task isn't already
    # queued to do so.
    for track in changed_tracks:
      deferred.defer(applesus.GenerateAppleSUSCatalogs, track=track, delay=180)
    # TODO(user): add a visual cue to UI so admins know a generation is pending.

    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(data))

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
      product_id = self.request.get('product_id')
      self._DisplayUpdateLogs(product_id=product_id)
    else:
      self.response.set_status(httplib.NOT_FOUND)

  def _DisplayMain(self):
    query = models.AppleSUSProduct.AllActive().order('-apple_mtime')
    products = []
    # NOTE(user): the following adds about 700ms onto the request, so we may
    #             want to pre-calculate this in a cron in the future.
    for p in gae_util.QueryIterator(query, step=100):
      if common.STABLE not in p.tracks:
        p.stable_promote_date = applesus.GetAutoPromoteDate(common.STABLE, p)
      if common.TESTING not in p.tracks:
        p.testing_promote_date = applesus.GetAutoPromoteDate(common.TESTING, p)
      products.append(p)

    catalogs = []
    for os_version in applesus.OS_VERSIONS:
      os_catalogs = {'os_version': os_version}
      for track in ['untouched'] + common.TRACKS:
        catalog_key = '%s_%s' % (os_version, track)
        c = models.AppleSUSCatalog.MemcacheWrappedGet(catalog_key)
        os_catalogs[track] = c.mtime if c else None
      catalogs.append(os_catalogs)

    catalogs_pending = {}
    for track in common.TRACKS:
      catalogs_pending[track] = False
      for os_version in applesus.OS_VERSIONS:
        lock_name = applesus.CatalogRegenerationLockName(track, os_version)
        catalogs_pending[track] |= gae_util.LockExists(lock_name)

    install_counts, counts_mtime = models.ReportsCache.GetInstallCounts()
    data = {
        'catalogs': catalogs,
        'catalogs_pending': catalogs_pending,
        'products': products,
        'install_counts': install_counts,
        'install_counts_mtime': counts_mtime,
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
    # replace escaped single-quotes, which may exist due to dist file structure.
    self.response.out.write(product.description.replace('\\\'', '\''))

  def _DisplayUpdateLogs(self, product_id=None):
    display_name = None
    logs_query = models.AdminAppleSUSProductLog.all()
    if product_id:
      logs_query.filter('product_id =', product_id)
      update_entity = models.AppleSUSProduct.get_by_key_name(product_id)
      if update_entity:
        display_name = '%s - %s' % (update_entity.name, update_entity.version)
    logs_query.order('-mtime')
    values = {
        'display_name': display_name,
        'product_id': product_id,
        'logs': self.Paginate(logs_query, DEFAULT_APPLESUS_LOG_FETCH),
        'report_type': 'apple_logs',
    }
    self.Render('applesus_log.html', values)
