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
"""Shared resources for handlers."""

import base64
import datetime
import logging

from google.appengine import runtime
from google.appengine.ext import db
from google.appengine.ext import deferred
from google.appengine.runtime import apiproxy_errors

from simian.mac import common
from simian.mac import models
from simian.mac.common import util
from simian.mac.munki import plist as plist_module


CLIENT_ID_FIELDS = {
    'uuid': str, 'owner': str, 'hostname': str, 'serial': str,
    'config_track': str, 'track': str, 'site': str,
    'os_version': str, 'client_version': str, 'on_corp': bool,
    'last_notified_datetime': str, 'uptime': float, 'root_disk_free': int,
    'user_disk_free': int, 'applesus': bool, 'runtype': str,
    'mgmt_enabled': bool,
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
FLASH_PLUGIN_NAME = 'flashplugin'
FLASH_PLUGIN_DEBUG_NAME = 'flash_player_debug'
# Apple Software Update pkgs_to_install text format.
APPLESUS_PKGS_TO_INSTALL_FORMAT = 'AppleSUS: %s'
# Serial numbers for which first connection de-duplication should be skipped.
DUPE_SERIAL_NUMBER_EXCEPTIONS = [
    'SystemSerialNumb', 'System Serial#', 'Not Available', None]


class Error(Exception):
  """Base Error."""


class ComputerNotFoundError(Error):
  """Computer could not be found."""


class ManifestNotFoundError(Error):
  """Manifest requested was not found."""


class ManifestDisabledError(Error):
  """Disable manifest was requested."""


def _SaveFirstConnection(client_id, computer_key):
  """Function to save first connection of a given client.

  Args:
    client_id: dict client id.
    computer_key: entity's key.
  """
  computer = models.Computer.get(computer_key)

  e = models.FirstClientConnection(key_name=client_id['uuid'])
  e.computer = computer
  e.owner = client_id['owner']
  e.hostname = client_id['hostname']
  e.site = client_id['site']
  e.put()

  # Set older computers with the same serial number as inactive.
  if computer.serial not in DUPE_SERIAL_NUMBER_EXCEPTIONS:
    for dupe in models.Computer.AllActive().filter('serial =', computer.serial):
      # skip over the new client.
      if dupe.uuid == computer.uuid:
        continue
      # if the dupe is clearly older, mark as inactive.
      if dupe.preflight_datetime < computer.preflight_datetime:
        dupe.active = False
        dupe.put(update_active=False)


def LogClientConnection(
    event, client_id, user_settings=None, pkgs_to_install=None,
    apple_updates_to_install=None, ip_address=None, report_feedback=None,
    computer=None, delay=0, cert_fingerprint=None):
  """Logs a host checkin to Simian.

  Args:
    event: str name of the event that prompted a client connection log.
    client_id: dict client id with fields: uuid, hostname, owner.
    user_settings: optional dict of user settings.
    pkgs_to_install: optional list of string packages remaining to install.
    apple_updates_to_install: optional list of string Apple updates remaining
        to install.
    ip_address: str IP address of the connection.
    report_feedback: dict ReportFeedback commands sent to the client.
    computer: optional models.Computer object.
    delay: int. if > 0, LogClientConnection call is deferred this many seconds.
    cert_fingerprint: optional str Client certificate fingerprint.
  """
  if delay:
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'log-client-conn-%s-%s' % (
        client_id['uuid'].replace('=', ''), now_str)
    deferred.defer(
        LogClientConnection, event, client_id, user_settings=user_settings,
        pkgs_to_install=pkgs_to_install, ip_address=ip_address,
        apple_updates_to_install=apple_updates_to_install,
        report_feedback=report_feedback, _name=deferred_name, _countdown=delay,
        cert_fingerprint=cert_fingerprint)
    return

  if not client_id['uuid']:
    logging.warning('LogClientConnection: uuid is unknown, skipping log')
    return

  def __UpdateComputerEntity(
      event, _client_id, _user_settings, _pkgs_to_install,
      _apple_updates_to_install, _ip_address, _report_feedback, c=None,
      cert_fingerprint=None):
    """Update the computer entity, or create a new one if it doesn't exists."""
    now = datetime.datetime.utcnow()
    is_new_client = False
    if c is None:
      c = models.Computer.get_by_key_name(_client_id['uuid'])
    if c is None:  # First time this client has connected.
      c = models.Computer(key_name=_client_id['uuid'])
      is_new_client = True
    c.uuid = _client_id['uuid']
    c.hostname = _client_id['hostname']
    c.serial= _client_id['serial']
    c.owner = _client_id['owner']
    c.track = _client_id['track']
    c.site = _client_id['site']
    c.config_track = _client_id['config_track']
    c.client_version = _client_id['client_version']
    c.os_version = _client_id['os_version']
    c.uptime = _client_id['uptime']
    c.root_disk_free = _client_id['root_disk_free']
    c.user_disk_free = _client_id['user_disk_free']
    c.runtype = _client_id['runtype']
    c.ip_address = _ip_address
    c.cert_fingerprint = cert_fingerprint

    last_notified_datetime = _client_id['last_notified_datetime']
    if last_notified_datetime:  # might be None
      try:
        last_notified_datetime = datetime.datetime.strptime(
            last_notified_datetime, '%Y-%m-%d %H:%M:%S')  # timestamp is UTC.
        c.last_notified_datetime = last_notified_datetime
      except ValueError:  # non-standard datetime sent.
        logging.warning(
            'Non-standard last_notified_datetime: %s', last_notified_datetime)

    # Update event specific (preflight vs postflight) report values.
    if event == 'preflight':
      c.preflight_datetime = now
      if _client_id['on_corp'] == True:
        c.last_on_corp_preflight_datetime = now

      # Increment the number of preflight connections since the last successful
      # postflight, but only if the current connection is not going to exit due
      # to report feedback (WWAN, GoGo InFlight, etc.)
      if not _report_feedback or not _report_feedback.get('exit'):
        if c.preflight_count_since_postflight is not None:
          c.preflight_count_since_postflight += 1
        else:
          c.preflight_count_since_postflight = 1

    elif event == 'postflight':
      c.preflight_count_since_postflight = 0
      c.postflight_datetime = now

      # Update pkgs_to_install.
      if _pkgs_to_install:
        c.pkgs_to_install = _pkgs_to_install
        c.all_pkgs_installed = False
      else:
        c.pkgs_to_install = []
        c.all_pkgs_installed = True
      # Update all_apple_updates_installed and add Apple updates to
      # pkgs_to_install. It's important that this code block comes after
      # all_pkgs_installed is updated above, to ensure that all_pkgs_installed
      # is only considers Munki updates, ignoring Apple updates added below.
      # NOTE: if there are any pending Munki updates then we simply assume
      # there are also pending Apple Updates, even though we cannot be sure
      # due to the fact that Munki only checks for Apple Updates if all regular
      # updates are installed
      if not pkgs_to_install and not _apple_updates_to_install:
        c.all_apple_updates_installed = True
      else:
        c.all_apple_updates_installed = False
        # For now, let's store Munki and Apple Update pending installs together,
        # using APPLESUS_PKGS_TO_INSTALL_FORMAT to format the text as desired.
        for update in _apple_updates_to_install:
          c.pkgs_to_install.append(APPLESUS_PKGS_TO_INSTALL_FORMAT % update)

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
    else:
      logging.warning('Unknown event value: %s', event)

    c.put()
    if is_new_client:  # Queue welcome email to be sent.
      deferred.defer(
          _SaveFirstConnection, client_id=_client_id, computer_key=c.key(),
          _countdown=300, _queue='first')

  try:
    db.run_in_transaction(
        __UpdateComputerEntity,
        event, client_id, user_settings, pkgs_to_install,
        apple_updates_to_install, ip_address, report_feedback, c=computer,
        cert_fingerprint=cert_fingerprint)
  except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError) as e:
    logging.warning(
        'LogClientConnection put() error %s: %s', e.__class__.__name__, str(e))
    LogClientConnection(
        event, client_id, user_settings, pkgs_to_install,
        apple_updates_to_install, ip_address, report_feedback,
        delay=DATASTORE_NOWRITE_DELAY)


def WriteClientLog(model, uuid, **kwargs):
  """Writes a ClientLog entry.

  Args:
    model: db.Model to write to.
    uuid: str uuid of client.
    **kwargs: property/value pairs to write to the model; uuid not allowed.
  Returns:
    models.Computer instance which is this client
  """
  if 'uuid' in kwargs:
    del kwargs['uuid']

  uuid = common.SanitizeUUID(uuid)

  if 'computer' not in kwargs:
    kwargs['computer'] = models.Computer.get_by_key_name(uuid)

  l = model(uuid=uuid, **kwargs)
  try:
    l.put()
  except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
    logging.warning('WriteClientLog put() failure; deferring...')
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    deferred_name = 'write-client-log-%s-%s' % (uuid.replace('=', ''), now_str)
    deferred.defer(
        WriteClientLog, model, uuid,
        _name=deferred_name, _countdown=5, **kwargs)

  return kwargs['computer']


def WriteBrokenClient(uuid, reason, details):
  """Saves a BrokenClient entity to Datastore for the given UUID.

  Args:
    uuid: str, uuid of client.
    reason: str, short description of broken state the client is reporting.
    details: str, details or debugging output of the broken report.
  """
  # If the details string contains facter output, parse it.
  facts = {}
  lines = details.splitlines()
  for line in lines:
    try:
      (key, unused_sep, value) = line.split(' ', 2)
    except ValueError:
      continue  # current line was not facter, continue.
    value = value.strip()
    facts[key] = value

  # Update the existing, or create a new ComputerClientBroken entity.
  uuid = common.SanitizeUUID(uuid)
  bc = models.ComputerClientBroken.get_or_insert(uuid)
  bc.broken_datetimes.append(datetime.datetime.utcnow())
  bc.reason = reason
  bc.details = details
  bc.fixed = False  # Previously fixed computers will show up again.
  bc.hostname = facts.get('hostname', '')
  bc.owner = facts.get('primary_user', '')
  bc.serial = facts.get('sp_serial_number', '')
  bc.uuid = uuid
  bc.put()


def WriteComputerMSULog(uuid, details):
  """Write log details from MSU GUI into ComputerMSULog model.

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
  c = models.ComputerMSULog(key_name=key)
  c.uuid = uuid
  c.event = details['event']
  c.source = details['source']
  c.user = details['user']
  c.desc = details['desc']
  try:
    mtime = util.Datetime.utcfromtimestamp(details.get('time', None))
  except ValueError, e:
    logging.warning('Ignoring msu_log time; %s' % str(e))
    mtime = datetime.datetime.utcnow()
  except util.EpochExtremeFutureValueError, e:
    logging.warning('Ignoring msu_log time; %s' % str(e))
    mtime = datetime.datetime.utcnow()
  except util.EpochValueError:
    mtime = datetime.datetime.utcnow()
  if c.mtime is None or mtime > c.mtime:
    c.mtime = mtime
    c.put()


def GetBoolValueFromString(s):
  """Returns True for true/1 strings, and False for false/0, None otherwise."""
  if s and s.lower() == 'true' or s == '1':
    return True
  elif s and s.lower() == 'false' or s == '0':
    return False
  else:
    return None


def KeyValueStringToDict(s, delimiter='|'):
  """Parses a key=value string with delimiter and returns a dict.

  Args:
    s: string with key=value pairs.
    delimiter: delimiter char(s) to parse the string with.
  Returns:
    dictionary of key value pairs. 'None' converted to None.
  """
  d = {}
  pairs = s.split(delimiter)
  for pair in pairs:
    try:
      key, value = pair.split('=', 1)
      if not value or value == 'None':
        value = None  # Convert empty strings to None.
      d[key] = value
    except ValueError:
      logging.debug('Ignoring invalid key/value pair: %s', pair)
  return d


def ParseClientId(client_id, uuid=None):
  """Splits a client id string and converts all key/value pairs to a dict.

  Also, this truncates string values to 500 characters.

  Args:
    client_id: string client id with "|" as delimiter.
    uuid: optional string uuid to override the uuid in client_id.
  Returns:
    Dict. Client id string "foo=bar|key=|one=1" yields
        {'foo': 'bar', 'key': None, 'one': '1'}.
  """
  if client_id and client_id.find('\n') > -1:
    logging.warning(
        'ParseClientId: client_id has newline: %s',
        base64.b64encode(client_id))
    client_id = client_id.replace('\n', '_')

  # Convert str input to unicode.
  if type(client_id) is str:
    try:
      client_id = client_id.decode('utf-8')
    except UnicodeDecodeError:
      client_id = client_id.decode('utf-8', 'replace')
      logging.warning('UnicodeDecodeError on client_id: %s', client_id)

  out = KeyValueStringToDict(client_id)

  # If any required fields were not present in the client id string, add them.
  # Also cast all values to their defined output types.
  for field, value_type in CLIENT_ID_FIELDS.iteritems():
    if field not in out or out[field] is None:
      out[field] = None
    elif value_type is bool:
      out[field] = GetBoolValueFromString(out[field])
    elif value_type is str:
      # truncate str fields to 500 characters, the StringProperty limit.
      out[field] = out[field][:500]
    else:
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
  """Returns True if in no package delivery mode."""
  return IsPanicMode(PANIC_MODE_NO_PACKAGES)


def SetPanicModeNoPackages(enabled):
  """Enable or disable no packages panic mode.

  Args:
    enabled: bool, to enable or disable the mode
  """
  SetPanicMode(PANIC_MODE_NO_PACKAGES, enabled)


def GetComputerManifest(uuid=None, client_id=None, packagemap=False):
  """For a computer uuid or client_id, return the current manifest.

  Args:
    uuid: str, computer uuid    OR
    client_id: dict, client_id
    packagemap: bool, default False, whether to return packagemap or not
  Returns:
    if packagemap, dict = {
        'plist': plist.MunkiManifestPlist instance,
        'packagemap': {   # if packagemap == True
            'Firefox': 'Firefox-3.x.x.x.dmg',
        },
    }

    if not packagemap, str, manifest plist
  Raises:
    ValueError: error in type of arguments supplied to this method
    ComputerNotFoundError: computer cannot be found for uuid
    ManifestNotFoundError: manifest requested is invalid (not found)
    ManifestDisabledError: manifest requested is disabled
  """
  if client_id is None and uuid is None:
    raise ValueError('uuid or client_id must be supplied')

  if client_id is not None:
    if type(client_id) is not dict:
      raise ValueError('client_id must be dict')
    uuid = client_id.get('uuid')

  user_settings = None
  if uuid is not None:
    c = models.Computer.get_by_key_name(uuid)
    if not c:
      raise ComputerNotFoundError

    user_settings = c.user_settings
    client_id = {
        'uuid': uuid,
        'owner': c.owner,
        'hostname': c.hostname,
        'serial': c.serial,
        'config_track': c.config_track,
        'track': c.track,
        'site': c.site,
        'os_version': c.os_version,
        'client_version': c.client_version,
        # TODO(user): Fix this; it may not be accurate.
        'on_corp': c.connections_on_corp > c.connections_off_corp,
        'last_notified_datetime': c.last_notified_datetime,
        'uptime': None,
        'root_disk_free': None,
        'user_disk_free': None,
    }

  # Step 1: Obtain a manifest for this uuid.
  manifest_plist_xml = None

  if IsPanicModeNoPackages():
    manifest_plist_xml = '%s%s' % (
        plist_module.PLIST_HEAD, plist_module.PLIST_FOOT)
  else:
    manifest_name = client_id['track']
    m = models.Manifest.MemcacheWrappedGet(manifest_name)
    if not m:
      raise ManifestNotFoundError(manifest_name)
    elif not m.enabled:
      raise ManifestDisabledError(manifest_name)

    manifest_plist_xml = GenerateDynamicManifest(
        m.plist, client_id, user_settings=user_settings)

  if not manifest_plist_xml:
    raise ManifestNotFoundError(manifest_name)

  # Step 1: Return now with xml if packagemap not requested.
  if not packagemap:
    return manifest_plist_xml

  # Step 2: Build lookup table from PackageName to PackageName-VersionNumber
  # for packages found in catalogs used by the client.

  manifest_plist = plist_module.MunkiManifestPlist(manifest_plist_xml)
  manifest_plist.Parse()

  packages = {}

  query = models.PackageInfo.all()
  for p in query:
    display_name = p.plist.get('display_name', None) or p.plist.get('name')
    display_name = display_name.strip()
    version = p.plist.get('version', '')
    packages[p.name] = '%s-%s' % (display_name, version)

  return {
      'plist': manifest_plist,
      'packagemap': packages,
  }


def _ModifyList(l, value):
  """Adds or removes a value from a list.

  Args:
    l: list to modify.
    value: str value; "foo" to add or "-foo" to remove "foo".
  """
  if value.startswith('-'):
    try:
      l.remove(value[1:])
    except ValueError:
      pass  # item is already not a member of the list, so ignore error.
  else:
    l.append(value)


def GenerateDynamicManifest(plist, client_id, user_settings=None):
  """Generate a dynamic manifest based on a the various client_id fields.

  Args:
    plist: str XML or plist_module.ApplePlist object, manifest to start with.
    client_id: dict client_id parsed by common.ParseClientId.
    user_settings: dict UserSettings as defined in Simian client.
  Returns:
    str XML manifest with any custom modifications based on the client_id.
  """
  # TODO(user): This function is getting out of control and needs refactoring.
  manifest = client_id['track']

  site_mods = models.SiteManifestModification.MemcacheWrappedGetAllFilter(
      (('site =', client_id['site']),))

  os_version_mods = \
      models.OSVersionManifestModification.MemcacheWrappedGetAllFilter(
          (('os_version =', client_id['os_version']),))

  owner_mods = models.OwnerManifestModification.MemcacheWrappedGetAllFilter(
      (('owner =', client_id['owner']),))

  uuid_mods = models.UuidManifestModification.MemcacheWrappedGetAllFilter(
      (('uuid =', client_id['uuid']),))

  tag_mods = []
  if client_id['uuid']:  # not set if viewing a base manifest.
    computer_key = models.db.Key.from_path('Computer', client_id['uuid'])
    computer_tags = models.Tag.GetAllTagNamesForKey(computer_key)
    if computer_tags:
      # NOTE(user): if we feel most computers will have tags, it might make
      #             sense to regularly fetch and cache all mods.
      for tag in computer_tags:
        t = (('tag_key_name =', tag),)
        tag_mods.extend(
            models.TagManifestModification.MemcacheWrappedGetAllFilter(t))

  group_mods = []
  if client_id['owner']:
    owner_groups = models.Group.GetAllGroupNamesForUser(client_id['owner'])
    if owner_groups:
      for group in owner_groups:
        g = (('group_key_name =', group),)
        group_mods.extend(
            models.GroupManifestModification.MemcacheWrappedGetAllFilter(g))

  def __ApplyModifications(manifest, mod, plist):
    """Applies a manifest modification if the manifest matches mod manifest.

    NOTE(user): if mod.manifests is empty or None, mod is made to any manifest.
    """
    plist_xml = None
    if type(plist) is str:
      plist_xml = plist

    if not mod.enabled:
      return  # return it the mod is disabled
    elif mod.manifests and manifest not in mod.manifests:
      return  # return if the desired manifest is not in the mod manifests.

    for install_type in mod.install_types:
      plist_module.UpdateIterable(
          plist, install_type, mod.value, default=[], op=_ModifyList)

  if (site_mods or owner_mods or os_version_mods or uuid_mods or tag_mods
      or group_mods):
    if type(plist) is str:
      plist = plist_module.MunkiManifestPlist(plist)
      plist.Parse()
    for mod in site_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in os_version_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in owner_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in uuid_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in tag_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in group_mods:
      __ApplyModifications(manifest, mod, plist)

  if user_settings:
    flash_developer = user_settings.get('FlashDeveloper', False)
    block_packages = user_settings.get('BlockPackages', [])
    # If plist is not parsed yet and modifications are required, parse it.
    if (flash_developer or block_packages) and type(plist) is str:
      if type(plist) is str:
        plist = plist_module.MunkiManifestPlist(plist)
        plist.Parse()

    # If FlashDeveloper is True, replace the regular flash plugin with the
    # debug version in managed_updates.
    if flash_developer:
      plist[common.MANAGED_UPDATES].append(FLASH_PLUGIN_DEBUG_NAME)
      try:
        plist[common.MANAGED_UPDATES].remove(FLASH_PLUGIN_NAME)
      except ValueError:
        pass  # FLASH_PLUGIN_NAME was not in managed_updates to begin with.

    # Look for each block package in each install type, remove if found.
    for block_package in block_packages:
      for install_type in common.INSTALL_TYPES:
        if block_package in plist.get(install_type, []):
          plist[install_type].remove(block_package)

  if type(plist) is str:
    return plist
  else:
    return plist.GetXml()
