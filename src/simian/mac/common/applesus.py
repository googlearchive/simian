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
"""Apple SUS shared functions."""

import datetime
import logging
import re
import xml
from xml.dom import minidom

from google.appengine.api import taskqueue
from google.appengine.ext import deferred

from simian.mac.common import datastore_locks
from simian import settings
from simian.mac import common
from simian.mac import models
from simian.mac.models import constants
from simian.mac.munki import plist


OS_VERSIONS = frozenset(['10.7', '10.8', '10.9', '10.10', '10.11', '10.12'])

_CATALOG_REGENERATION_LOCK_NAME = 'applesus_catalog_regeneration_%s_%s'

MON, TUE, WED, THU, FRI, SAT, SUN = range(0, 7)


def CatalogRegenerationLockName(track, os_version):
  return _CATALOG_REGENERATION_LOCK_NAME % (
      track, os_version.replace('.', '-'))


class Error(Exception):
  """Base error."""


class DocumentFormatError(Error):
  """Error in document format."""


class DistFileDocument(object):
  """Class to hold a Apple SUS distfile document."""

  def __init__(self):
    """Initializer."""
    self.Reset()

  def Reset(self):
    """Reset variables."""
    self.description = None
    self.restart_required = None
    self.server_comment = None
    self.softwareupdate_name = None
    self.title = None
    self.version = None

    self._installer_script = {}

  def _ParseInstallerScriptString(self, istr):
    """Parse an installer script string and return its key/value pairs.

    The installer script string appears generally as
      "KEY" = "VALUE"
    and can contain multiple lines. Apparently the quoting chars can be
    double or single quotes, and the alternative quote char is allowed as
    a literal inside the other.

    Standard javascript-style comments are permitted.

    Poorly formed lines will disrupt the parser and incomplete/no values
    will be returned.

    For example:

        // This comment is OK
        "KEY" = "VALUE";
        "KEY2" = "VALUE2";

        // Here's another comment later on.
        "KEY3" = 'VALUE3
        VALUE3MORE "THIS IS VALID"
        ';

    Or, consider:

        "KEY" = ;         # this will break the parser
        "NOTFOUNDKEY" = "NEVER GET HERE";

    Args:
      istr: str, see above format example above.
    Returns:
      dict
    """
    installer_script = {}

    kv_split = re.compile(
        (r'(?:^//[^\n]*$)|'
         '(?:^"(\w+)"\s*=\s*([\"\'])([^\\2]*?)\\2;$)'),
        re.MULTILINE | re.DOTALL)

    for i in re.finditer(kv_split, istr):
      if i.group(1):
        installer_script[i.group(1)] = i.group(3)

    return installer_script

  def LoadDocument(self, distfile_xml):
    """Load an entire distfile XML document and parse it.

    Args:
      distfile_xml: str, xml document
    Raises:
      DocumentFormatError: the XML document is malformed.
    """
    try:
      p = minidom.parseString(distfile_xml)
    except xml.parsers.expat.ExpatError, e:
      raise DocumentFormatError(str(e))

    try:
      l = p.getElementsByTagName('localization')[0]
      s = p.getElementsByTagName('strings')[0]
      cdata = []
      for cn in s.childNodes:
        cdata.append(cn.nodeValue)
      cdata = ''.join(cdata)
    except IndexError:
      raise DocumentFormatError

    # TODO(user): intead of regex, parse XML.
    self.restart_required = re.search(
        r'onConclusion=("|\')RequireRestart("|\')', distfile_xml) is not None

    swupd_name_match = re.search(
        r'suDisabledGroupID=("|\')([\w\s\.-]*)("|\')', distfile_xml)
    if swupd_name_match:
      self.softwareupdate_name = swupd_name_match.group(2)

    self._installer_script = self._ParseInstallerScriptString(cdata)

    self.description = self._installer_script.get('SU_DESCRIPTION')
    self.server_comment = self._installer_script.get('SU_SERVERCOMMENT')
    self.title = self._installer_script.get('SU_TITLE')
    self.version = (self._installer_script.get('SU_VERS') or
                    self._installer_script.get('SU_VERSION'))


def GenerateAppleSUSCatalogs(track=None, tracks=None, delay=0):
  """Generates Apple SUS catalogs for a given track, set of tracks, or all.
  Note: this generates tracks for all os_versions on the given track/tracks.

  Args:
    track: string track to generate catalog for. OR,
    tracks: list of string tracks.
    delay: int. if > 0, defer generating the catalogs by this many seconds.
  """
  if track and tracks:
    raise ValueError('only one of track and tracks is allowed')
  elif not tracks and not track:
    tracks = common.TRACKS
  elif track:
    tracks = [track]

  for track in tracks:
    for os_version in OS_VERSIONS:
      lock_name = CatalogRegenerationLockName(track, os_version)
      lock = datastore_locks.DatastoreLock(lock_name)
      try:
        lock.Acquire(timeout=600 + delay, max_acquire_attempts=1)
      except datastore_locks.AcquireLockError:
        continue
      if delay:
        now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
        deferred_name = 'gen-applesus-catalog-%s-%s-%s' % (
            os_version, track, now_str)
        deferred_name = re.sub(r'[^\w-]', '', deferred_name)
        try:
          deferred.defer(
              GenerateAppleSUSCatalog, os_version, track, catalog_lock=lock,
              _countdown=delay, _name=deferred_name)
        except taskqueue.TaskAlreadyExistsError:
          logging.info('Skipping duplicate Apple SUS Catalog generation task.')
      else:
        GenerateAppleSUSCatalog(os_version, track, catalog_lock=lock)

  if delay:
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'gen-sus-metadata-catalog-%s' % now_str
    deferred_name = re.sub(r'[^\w-]', '', deferred_name)
    try:
      deferred.defer(
          GenerateAppleSUSMetadataCatalog, _name=deferred_name)
    except taskqueue.TaskAlreadyExistsError:
      logging.info('Skipping duplicate Apple SUS Catalog generation task.')
  else:
    GenerateAppleSUSMetadataCatalog()


def GenerateAppleSUSCatalog(
    os_version, track, datetime_=datetime.datetime, catalog_lock=None):
  """Generates an Apple SUS catalog for a given os_version and track.

  This function loads the untouched/raw Apple SUS catalog, removes any
  products/updates that are not approved for the given track, then saves
  a new catalog (plist/xml) to Datastore for client consumption.

  Args:
    os_version: str OS version to generate the catalog for.
    track: str track name to generate the catalog for.
    datetime_: datetime module; only used for stub during testing.
    catalog_lock: datastore_lock.DatastoreLock; If provided, the lock to release
                  upon completion of the operation.
  Returns:
    tuple, new models.AppleSUSCatalog object and plist.ApplePlist object. Or,
    if there is no "untouched" catalog for the os_version, then (None, None) is
    returned.
  """
  logging.info('Generating catalog: %s_%s', os_version, track)

  catalog_key = '%s_untouched' % os_version
  untouched_catalog_obj = models.AppleSUSCatalog.get_by_key_name(catalog_key)
  if not untouched_catalog_obj:
    logging.warning('Apple Update catalog does not exist: %s', catalog_key)
    if catalog_lock:
      catalog_lock.Release()
    return None, None
  untouched_catalog_plist = plist.ApplePlist(untouched_catalog_obj.plist)
  untouched_catalog_plist.Parse()

  approved_product_ids = set()
  products_query = models.AppleSUSProduct.AllActive().filter('tracks =', track)
  for product in products_query:
    approved_product_ids.add(product.product_id)

  product_ids = untouched_catalog_plist.get('Products', {}).keys()
  new_plist = untouched_catalog_plist
  for product_id in product_ids:
    if product_id not in approved_product_ids:
      del new_plist['Products'][product_id]

  catalog_plist_xml = new_plist.GetXml()

  # Save the catalog using a time-specific key for rollback purposes.
  now = datetime_.utcnow()
  now_str = now.strftime('%Y-%m-%d-%H-%M-%S')
  backup = models.AppleSUSCatalog(
      key_name='backup_%s_%s_%s' % (os_version, track, now_str))
  backup.plist = catalog_plist_xml
  backup.put()
  # Overwrite the catalog being served for this os_version/track pair.
  c = models.AppleSUSCatalog(key_name='%s_%s' % (os_version, track))
  c.plist = catalog_plist_xml
  c.put()

  if catalog_lock:
    catalog_lock.Release()

  return c, new_plist


def GenerateAppleSUSMetadataCatalog():
  """Generates the Apple SUS metadata catalog.

  Returns:
    The Catalog instance created.
  """
  logging.info('Generating catalog: apple_update_metadata')

  products = {}
  # Currently, items need to exist in this catalog if they're unattended or
  # have a force_install_after_date date set.
  unattended = models.AppleSUSProduct.AllActive().filter('unattended =', True)
  force_install_after_date = models.AppleSUSProduct.AllActive().filter(
      'force_install_after_date !=', None)
  for p in unattended:
    products[p.product_id] = p
  for p in force_install_after_date:
    products[p.product_id] = p

  catalog_plist_xml_fragments = [
      p.plist.GetXmlContent() for p in products.values()]
  catalog_plist_xml = constants.CATALOG_PLIST_XML % (
      '\n'.join(catalog_plist_xml_fragments))

  # Overwrite the catalog being served for this os_version/track pair.
  c = models.Catalog(key_name='apple_update_metadata')
  c.plist = catalog_plist_xml
  c.put()
  models.Catalog.DeleteMemcacheWrap(
      'apple_update_metadata', prop_name='plist_xml')
  return c


def GetAutoPromoteDate(track, applesus_product):
  """Returns a date of when a given update will auto-promote.

  Args:
    track: str track to get the auto-promote datetime for.
    applesus_product: models.AppleSUSProduct object.
  Returns:
    datetime.date of when the Apple SUS update will be auto-promoted to track,
    or None if the product will never be auto-promoted due to manual_override or
    the product not being in the unstable track.
  Raises:
    ValueError: an invalid track was specified; only testing/stable supported.
  """
  if not settings.APPLE_AUTO_PROMOTE_ENABLED:
    return None
  if applesus_product.manual_override:
    return None
  elif common.UNSTABLE not in applesus_product.tracks:
    return None

  if track == common.TESTING:
    days = settings.APPLE_UNSTABLE_GRACE_PERIOD_DAYS
  elif track == common.STABLE:
    days = settings.APPLE_TESTING_GRACE_PERIOD_DAYS
  else:
    raise ValueError('Invalid track was specified: %s' % track)

  auto_promote_offset = datetime.timedelta(days=days)
  previous_track_date = applesus_product.mtime.date()

  if track == common.TESTING:
    auto_promote_date = previous_track_date + auto_promote_offset
    if auto_promote_date.weekday() >= SAT:  # Sat or Sun.
      auto_promote_date = _GetNextWeekdayDate(
          weekday=MON, min_date=auto_promote_date)
    return auto_promote_date

  # If we're looking for a stable auto-promotion date but the item is not yet in
  # testing, then we need to first figure out when it will go to testing and set
  # the previous_track_mtime to that.
  if common.TESTING not in applesus_product.tracks:
    previous_track_date = GetAutoPromoteDate('testing', applesus_product)

  # Unstable should only promoted on Wednesdays and only after the grace period.
  min_auto_promote_date = previous_track_date + auto_promote_offset
  return _GetNextWeekdayDate(
      weekday=settings.APPLE_AUTO_PROMOTE_STABLE_WEEKDAY,
      min_date=min_auto_promote_date)


def _GetNextWeekdayDate(weekday, min_date=None):
  """Returns the date of the current or next weekday on or after min_date.

  Args:
    weekday: int weekday number, where Monday is 0 and Sunday is 6.
    min_date: datetime.date object of the minimum date to find the weekday on
        or after. default of None uses today as the minimum date.
  Returns:
    datetime.date object of the current or next desired weekday.
  """
  if min_date is None:
    min_date = datetime.datetime.utcnow().date()

  next_date = min_date

  if min_date.weekday() > weekday:
    next_date += datetime.timedelta(7 - min_date.weekday() + weekday)
  else:
    next_date += datetime.timedelta(weekday - min_date.weekday())

  return next_date
