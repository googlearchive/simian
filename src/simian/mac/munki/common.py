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

"""Shared resources for handlers."""



import datetime
import logging
import time
from google.appengine.ext import db
from google.appengine.ext import deferred
from google.appengine.api import memcache
from google.appengine import runtime
from google.appengine.runtime import apiproxy_errors
from simian.mac import models
from simian.mac import common
from simian.mac.munki import plist as plist_module


CLIENT_ID_FIELDS = {
    'uuid': str, 'owner': str, 'hostname': str, 'config_track': str,
    'track': str, 'site': str, 'office': str, 'os_version': str,
    'client_version': str, 'on_corp': lambda x: bool(int(x)),
    'last_notified_datetime': str, 'uptime': float, 'root_disk_free': int,
    'user_disk_free': int,
}
CONNECTION_DATETIMES_LIMIT = 10
CONNECTION_DATES_LIMIT = 30
# If the datastore goes write-only, delay a write for x seconds:
DATASTORE_NOWRITE_DELAY = 60
# Panic mode prefix for key names in KeyValueCache
PANIC_MODE_PREFIX = 'panic_mode_'
# Panic mode which disables all packages
PANIC_MODE_NO_PACKAGES = 'no_packages'
PANIC_MODES = [PANIC_MODE_NO_PACKAGES]


class Error(Exception):
  """Base Error."""


class CatalogCreationError(Error):
  """There was an error generating a catalog."""


class ManifestCreationError(Error):
  """There was an error updating the manifest."""


# Munki catalog plist XML with Apple DTD/etc, and empty array for filling.
CATALOG_PLIST_XML = '%s<array>\n  %s\n</array>%s' % (
    plist_module.PLIST_HEAD, '%s', plist_module.PLIST_FOOT)


def ObtainLock(name, timeout=0):
  """Obtain a lock, given a name.

  Args:
    name: str, name of lock
    timeout: int, if >0, wait timeout seconds for a lock if it cannot
      be obtained at first attempt.  NOTE:  Using a timeout near or greater
      than the AppEngine deadline will be hazardous to your health.
      The deadline is 30s for live http, 10m for offline tasks as of
      this note.
  Returns:
    True if lock was obtained
    False if lock was not obtained, some other process has the lock
  """
  memcache_key = 'lock_%s' % name
  while 1:
    locked = memcache.incr(memcache_key, initial_value=0) == 1
    timeout -= 1
    if locked or timeout < 0:
      return locked
    time.sleep(1)
  return False


def ReleaseLock(name):
  """Release a lock, given its name.

  Args:
    name: str, name of lock
  """
  memcache_key = 'lock_%s' % name
  memcache.delete(memcache_key)


def CreateManifest(name, delay=0):
  """Creates a manifest from available and matching PackageInfo entities.

  Args:
    name: str manifest name.
    delay: int. if > 0, AddPackageToManifest call is deferred this many seconds.
  """
  if delay:
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'create-manifest-%s-%s' % (name, now_str)
    deferred.defer(CreateManifest, name, _name=deferred_name, _countdown=delay)
    return

  lock = 'manifest_lock_%s' % name
  if not ObtainLock(lock):
    logging.debug(
        'CreateManifest for %s is locked. Delaying....', name)
    CreateManifest(name, delay=5)
    return

  logging.debug('Creating manifest: %s', name)
  try:
    package_infos = models.PackageInfo.all().filter('manifests =', name)
    if not package_infos:
      # TODO(user): if this happens we probably want to notify admins...
      raise ManifestCreationError('PackageInfo entities found: %s' % name)

    install_types = {}
    for p in package_infos:
      # Add all installs to their appropriate install type containers.
      for install_type in p.install_types:
        if install_type not in install_types:
          install_types[install_type] = []
        install_types[install_type].append(p.name)

    # Generate a dictionary of the manifest data.
    manifest_dict = {'catalogs': [name]}
    for k, v in install_types.iteritems():
      manifest_dict[k] = v
    # Turn the manifest dictionary into XML.
    manifest = plist_module.MunkiManifestPlist()
    manifest.SetContents(manifest_dict)

    # Save the new manifest to Datastore.
    manifest_entity = models.Manifest.get_or_insert(name)
    manifest_entity.plist = manifest.GetXml()
    manifest_entity.put()
    models.Manifest.ResetMemcacheWrap(name)
    logging.debug(
        'Manifest %s created successfully', name)
  except (ManifestCreationError, db.Error, plist_module.Error):
    logging.exception('CreateManifest failure: %s', name)
    ReleaseLock(lock)
    raise
  ReleaseLock(lock)


def CreateCatalog(name, delay=0):
  """Creates a catalog from pkgsinfo plists.

  Args:
    name: str catalog name.
    delay: int. if > 0, CreateCatalog call is deferred this many seconds.
  """
  if delay:
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'create-catalog-%s-%s' % (name, now_str)
    deferred.defer(CreateCatalog, name, _name=deferred_name, _countdown=delay)
    return

  lock = 'catalog_lock_%s' % name
  # Obtain a lock on the catalog name.
  if not ObtainLock(lock):
    # If catalog creation for this name is already in progress then delay.
    logging.debug('Catalog creation for %s is locked. Delaying....', name)
    CreateCatalog(name, delay=5)
    return

  logging.debug('Creating catalog: %s', name)
  try:
    pkgsinfo_dicts = []
    package_infos = models.PackageInfo.all().filter('catalogs =', name)
    if not package_infos:
      # TODO(user): if this happens we probably want to notify admins...
      raise CatalogCreationError('No pkgsinfo found with catalog: %s' % name)

    for p in package_infos:
      apl = plist_module.ApplePlist(p.plist)
      apl.Parse()
      pkgsinfo_dicts.append(apl.GetXmlContent())

    catalog = CATALOG_PLIST_XML % '\n  '.join(pkgsinfo_dicts)

    c = models.Catalog.get_or_insert(name)
    c.name = name
    c.plist = catalog
    c.put()
    models.Catalog.ResetMemcacheWrap(name)
    logging.debug('Created catalog successfully: %s', name)
    # Create manifest for newly generated catalog.
    CreateManifest(name, delay=1)
  except (CatalogCreationError, db.Error, plist_module.Error):
    logging.exception('CreateCatalog failure for catalog: %s', name)
    ReleaseLock(lock)
    raise
  ReleaseLock(lock)


def _SaveFirstConnection(client_id, computer):
  """Function to save first connection of a given client.

  Args:
    client_id: dict client id.
    computer: models.Computer entity.
  """
  logging.debug('Saving first connection for: %s' % client_id)
  e = models.FirstClientConnection(key_name=client_id['uuid'])
  e.computer = computer
  e.owner = client_id['owner']
  e.hostname = client_id['hostname']
  e.office = client_id['office']
  e.site = client_id['site']
  e.put()


def LogClientConnection(event, client_id, user_settings, delay=0):
  """Logs a host checkin to Simian.

  Args:
    event: str name of the event that prompted a client connection log.
    client_id: dict client id with fields: uuid, hostname, owner.
    delay: int. if > 0, LogClientConnection call is deferred this many seconds.
  """
  logging.debug(
      'LogClientConnection(%s, %s, user_settings? %s, delay=%s)',
      event, client_id, user_settings not in [None, {}], delay)

  if delay:
    logging.debug('Delaying LogClientConnection call %s seconds', delay)
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'log-client-conn-%s-%s' % (client_id['uuid'], now_str)
    deferred.defer(
        LogClientConnection, event, client_id, user_settings,
        _name=deferred_name, _countdown=delay)
    return

  if not client_id['uuid']:
    logging.debug('uuid is unknown, skipping log.')
    return

  def __UpdateComputerEntity(event, _client_id, _user_settings):
    """Update the computer entity, or create a new one if it doesn't exists."""
    now = datetime.datetime.utcnow()
    c = models.Computer.get_by_key_name(_client_id['uuid'])
    is_new_client = False
    if c is None:  # First time this client has connected.
      c = models.Computer(key_name=_client_id['uuid'])
      is_new_client = True
    c.uuid = _client_id['uuid']
    c.hostname = _client_id['hostname']
    c.owner = _client_id['owner']
    c.track = _client_id['track']
    c.site = _client_id['site']
    c.office = _client_id['office']
    c.config_track = _client_id['config_track']
    c.client_version = _client_id['client_version']
    c.os_version = _client_id['os_version']
    c.uptime = _client_id['uptime']
    c.root_disk_free = _client_id['root_disk_free']
    c.user_disk_free = _client_id['user_disk_free']

    last_notified_datetime = _client_id['last_notified_datetime']
    if last_notified_datetime:  # might be None
      try:
        last_notified_datetime = datetime.datetime.strptime(
            last_notified_datetime, '%Y-%m-%d %H:%M:%S')  # timestamp is UTC.
        c.last_notified_datetime = last_notified_datetime
      except ValueError:  # non-standard datetime sent.
        logging.warning(
            'Non-standard last_notified_datetime: %s', last_notified_datetime)

    # Update the appropriate datetime, preflight/postflight.
    if event == 'preflight':
      c.preflight_datetime = now
    elif event == 'postflight':
      c.postflight_datetime = now
    else:
      logging.warning('Unknown event value: %s', event)

    # Update the connection dates/etc only if postflight is calling log.
    if event == 'postflight':
      # Keep the last CONNECTION_DATETIMES_LIMIT connection datetimes.
      if len(c.connection_datetimes) == CONNECTION_DATETIMES_LIMIT:
        c.connection_datetimes.pop(0)
      c.connection_datetimes.append(now)

      # Increase on_corp/off_corp count appropriately.
      if _client_id['on_corp'] == True:
        c.connections_on_corp = (c.connections_on_corp or 0) + 1
      elif _client_id['on_corp'] == False:
        c.connections_off_corp = (c.connections_off_corp or 0) + 1

      # Keep the last CONNECTION_DATES_LIMIT connection dates
      # (with time = 00:00:00)
      # Use newly created datetime.time object to set time to 00:00:00
      now_date = datetime.datetime.combine(now, datetime.time())
      if now_date not in c.connection_dates:
        if len(c.connection_dates) == CONNECTION_DATES_LIMIT:
          c.connection_dates.pop(0)
        c.connection_dates.append(now_date)

    c.put()
    if is_new_client:  # Queue welcome email to be sent.
      logging.debug('Deferring _SaveFirstConnection....')
      deferred.defer(
          _SaveFirstConnection, client_id=_client_id, computer=c,
          _countdown=300, _queue='first')

  try:
    db.run_in_transaction(
        __UpdateComputerEntity,
        event, client_id, user_settings)
    # to run w/o transaction:
    # __UpdateComputerEntity(event, client_id, user_settings)
  except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
    logging.warning('LogClientConnection put() failure; deferring...')
    LogClientConnection(
        event, client_id, user_settings, delay=DATASTORE_NOWRITE_DELAY)


def WriteClientLog(model, uuid, **kwargs):
  """Writes a ClientLog entry.

  Args:
    model: db.Model to write to.
    uuid: str uuid of client.
    kwargs: property/value pairs to write to the model; uuid not allowed.
  Returns:
    models.Computer instance which is this client
  """
  if 'uuid' in kwargs:
    logging.warning('Deleting uuid from kwargs in WriteClientLog call.')
    del(kwargs['uuid'])

  uuid = common.SanitizeUUID(uuid)

  if 'computer' not in kwargs:
    kwargs['computer'] =  models.Computer.get_by_key_name(uuid)

  l = model(uuid=uuid, **kwargs)
  try:
    l.put()
  except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
    logging.warning('WriteClientLog put() failure; deferring...')
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'write-client-log-%s-%s' % (uuid, now_str)
    deferred.defer(
        WriteClientLog, model, uuid,
        _name=deferred_name, _countdown=5, **kwargs)

  return kwargs['computer']


def WriteBrokenClient(details):
  """Parses facter facts and saves a BrokenClient entity.

  This point of doing this over simply using WriteClientLog is that we have a
  single entry for each unique broken client instead of a entry for each report,
  and we can manually mark them fixed to exclude them from a report of currently
  broken clients.

  Args:
    details: str output of facter.
  """
  facts = {}
  lines = details.splitlines()
  for line in lines:
    try:
      (key, unused_sep, value) = line.split(' ', 2)
    except ValueError:
      continue  # current line was not facter, continue.
    value = value.strip()
    facts[key] = value

  uuid = facts.get('certname', None)
  if uuid:
    uuid = common.SanitizeUUID(uuid)
    bc = models.ComputerClientBroken.get_or_insert(uuid)
  else:
    bc = models.ComputerClientBroken()
  bc.hostname = facts.get('hostname', '')
  bc.owner = facts.get('primary_user', '')
  bc.details = details
  bc.fixed = False
  bc.uuid = uuid
  bc.broken_datetimes.append(datetime.datetime.utcnow())
  bc.put()


def WriteComputerMSULog(uuid, details):
  """Write log details from MSU GUI into ComputerMSUState model.

  Args:
    uuid: str, computer uuid to update
    details: dict like = {
      'event': str, 'something_happened',
      'source': str, 'MSU' or 'user',
      'user': str, 'username',
      'time': int, epoch seconds,
      'desc': str, 'additional descriptive text',
    }
  """
  uuid = common.SanitizeUUID(uuid)
  key = '%s_%s_%s' % (uuid, details['source'], details['event'])
  c = models.ComputerMSULog.get_or_insert(key)
  c.uuid = uuid
  c.event = details['event']
  c.source = details['source']
  c.user = details['user']
  c.desc = details['desc']
  new_dt = datetime.datetime(*time.gmtime(details['time'])[0:6])
  if c.mtime is None or new_dt > c.mtime:
    c.mtime = new_dt
    c.put()


def ParseClientId(client_id, uuid=None):
  """Splits a client id string and converts all key/value pairs to a dict.

  Args:
    client_id: string client id with "|" as delimiter.
    uuid: optional string uuid to override the uuid in client_id.
  Returns:
    Dict. Client id string "foo=bar|key=|one=1" yields
        {'foo': 'bar', 'key': None, 'one': '1'}.
  """
  out = {}
  pairs = client_id.split('|')
  for pair in pairs:
    try:
      key, value = pair.split('=', 1)
      if not value or value == 'None':
        value = None  # Convert empty strings to None.
      out[key] = value
    except ValueError:
      logging.warning('Ignoring invalid key/value pair in client id: %s', pair)

  # If any required fields were not present in the client id string, add them.
  # Also cast all values to their defined output types.
  for field, value_type in CLIENT_ID_FIELDS.iteritems():
    if field not in out:
      out[field] = None
    elif out[field] is not None and value_type is not str:
      try:
        out[field] = value_type(out[field])
      except ValueError:
        logging.warning(
            'Error casting client id %s to defined type: %s', field, out[field])
        out[field] = None

  if out['track'] not in common.TRACKS:
    if out['track'] is not None:
      logging.warning('Invalid track requested: %s', out['track'])
    out['track'] = common.DEFAULT_TRACK

  if uuid:
    out['uuid'] = common.SanitizeUUID(uuid)

  return out


def IsPanicMode(mode):
  """Returns True if panic mode, False if not.

  Args:
    mode: str
  Returns:
    True or False
  """
  if mode not in PANIC_MODES:
    raise ValueError(mode)

  m = models.KeyValueCache.MemcacheWrappedGet(
      '%s%s' % (PANIC_MODE_PREFIX, mode))
  if m:
    return True
  else:
    return False


def SetPanicMode(mode, enabled):
  """Set a panic mode on or off.

  Args:
    mode: str, mode to set
    enabled: bool, to enable or disable the mode
  """
  if mode not in PANIC_MODES:
    raise ValueError(mode)

  q = models.KeyValueCache.get_by_key_name('%s%s' % (PANIC_MODE_PREFIX, mode))

  if enabled:
    if not q:
      q = models.KeyValueCache(key_name='%s%s' % (PANIC_MODE_PREFIX, mode))
      q.text_value = '1'
      q.put()
  else:
    if q:
      q.delete()

  models.KeyValueCache.ResetMemcacheWrap('%s%s' % (PANIC_MODE_PREFIX, mode))


def IsPanicModeNoPackages():
  """Returns True if Macsimian is in no package delivery mode."""
  return IsPanicMode(PANIC_MODE_NO_PACKAGES)


def SetPanicModeNoPackages(enabled):
  """Enable or disable no packages panic mode.

  Args:
    enabled: bool, to enable or disable the mode
  """
  SetPanicMode(PANIC_MODE_NO_PACKAGES, enabled)