#!/usr/bin/env python
#
# Copyright 2017 Google Inc. All Rights Reserved.
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
"""App Engine Models for Simian web application."""

import datetime
import difflib
import gc
import logging
import re

from google.appengine.api import memcache
from google.appengine.ext import db

from simian.mac.common import ipcalc
from simian.mac.common import gae_util
from simian.mac.common import util
from simian.mac.models import properties
from simian.mac.munki import plist as plist_lib


class Error(Exception):
  """Class for domain exceptions."""


class InvalidArgumentsError(Error):
  """Invalid arguments were passed."""


# The number of days a client is silent before being considered inactive.
COMPUTER_ACTIVE_DAYS = 30
# Default memcache seconds for memcache-backed datastore entities
MEMCACHE_SECS = 300


class BaseModel(db.Model):
  """Abstract base model with useful generic methods."""

  @classmethod
  def DeleteMemcacheWrap(cls, key_name, prop_name=None):
    """Deletes a cached entity or property from memcache.

    Args:
      key_name: str key name of the entity to delete.
      prop_name: optional, default None, property name to delete.
    """
    if prop_name:
      memcache_key = 'mwgpn_%s_%s_%s' % (cls.kind(), key_name, prop_name)
    else:
      memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    memcache.delete(memcache_key)

  @classmethod
  def ResetMemcacheWrap(
      cls, key_name, prop_name=None, memcache_secs=MEMCACHE_SECS):
    """Deletes and repopulates a cached entity or property from Datastore.

    Args:
      key_name: str key name of the entity to delete.
      prop_name: optional, default None, property name to delete.
      memcache_secs: int seconds to store in memcache; default MEMCACHE_SECS.
    """
    cls.DeleteMemcacheWrap(key_name, prop_name=prop_name)
    cls.MemcacheWrappedGet(
        key_name, prop_name=prop_name, memcache_secs=memcache_secs)

  @classmethod
  def MemcacheWrappedGet(
      cls, key_name, prop_name=None, memcache_secs=MEMCACHE_SECS,
      retry=False):
    """Fetches an entity by key name from model wrapped by Memcache.

    Args:
      key_name: str key name of the entity to fetch.
      prop_name: optional property name to return the value for instead of
        returning the entire entity.
      memcache_secs: int seconds to store in memcache; default MEMCACHE_SECS.
      retry: bool, default False, if this is a retry (2nd attempt) to
        MemcacheWrappedGet the entity.
    Returns:
      If an entity for key_name exists,
        if prop_name == None returns the db.Model entity,
        otherwise only returns the prop_name property value on entity.
      If an entity for key_name does not exist,
        returns None.
    """
    output = None
    if prop_name:
      memcache_key = 'mwgpn_%s_%s_%s' % (cls.kind(), key_name, prop_name)
    else:
      memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)

    cached = memcache.get(memcache_key)

    if cached is None:
      entity = cls.get_by_key_name(key_name)
      if not entity:
        return

      if prop_name:
        try:
          output = getattr(entity, prop_name)
        except AttributeError:
          logging.error(
              'Retrieving missing property %s on %s',
              prop_name,
              entity.__class__.__name__)
          return
        to_cache = output
      else:
        output = entity
        to_cache = db.model_to_protobuf(entity).SerializeToString()

      try:
        memcache.set(memcache_key, to_cache, memcache_secs)
      except ValueError, e:
        logging.warning(
            'MemcacheWrappedGet: failure to memcache.set(%s, ...): %s',
            memcache_key, str(e))
    else:
      if prop_name:
        output = cached
      else:
        try:
          output = db.model_from_protobuf(cached)
        except Exception, e:  # pylint: disable=broad-except
          # NOTE(user): I copied this exception trap style from
          # google.appengine.datastore.datatstore_query.  The notes indicate
          # that trapping this exception by the class itself is problematic
          # due to differences between the Python and SWIG'd exception
          # classes.
          output = None
          memcache.delete(memcache_key)
          if e.__class__.__name__ == 'ProtocolBufferDecodeError':
            logging.warning('Invalid protobuf at key %s', key_name)
          elif retry:
            logging.exception('Unexpected exception in MemcacheWrappedGet')
          if not retry:
            return cls.MemcacheWrappedGet(
                key_name, prop_name=prop_name, memcache_secs=memcache_secs,
                retry=True)
          else:
            return cls.get_by_key_name(key_name)

    return output

  @classmethod
  def MemcacheWrappedGetAllFilter(
      cls, filters=(), limit=1000, memcache_secs=MEMCACHE_SECS):
    """Fetches all entities for a filter set, wrapped by Memcache.

    Args:
      filters: tuple, optional, filter arguments, e.g.
        ( ( "foo =", True ),
          ( "zoo =", 1 ), ),
      limit: int, number of rows to fetch
      memcache_secs: int seconds to store in memcache; default MEMCACHE_SECS.
    Returns:
      entities
    """
    filter_str = '|'.join(map(lambda x: '_%s,%s_' % (x[0], x[1]), filters))
    memcache_key = 'mwgaf_%s%s' % (cls.kind(), filter_str)

    entities = memcache.get(memcache_key)
    if entities is None:
      query = cls.all()
      for filt, value in filters:
        query = query.filter(filt, value)
      entities = query.fetch(limit)
      memcache.set(memcache_key, entities, memcache_secs)

    return entities

  @classmethod
  def DeleteMemcacheWrappedGetAllFilter(cls, filters=()):
    """Deletes the memcache wrapped response for this GetAllFilter.

    Args:
      filters: tuple, optional, filter arguments, e.g.
        ( ( "foo =", True ),
          ( "zoo =", 1 ), ),
    """
    filter_str = '|'.join(map(lambda x: '_%s,%s_' % (x[0], x[1]), filters))
    memcache_key = 'mwgaf_%s%s' % (cls.kind(), filter_str)
    memcache.delete(memcache_key)

  @classmethod
  def MemcacheWrappedSet(
      cls, key_name, prop_name, value, memcache_secs=MEMCACHE_SECS):
    """Sets an entity by key name and property wrapped by Memcache.

    Args:
      key_name: str, key name of entity to fetch
      prop_name: str, property name to set with value
      value: object, value to set
      memcache_secs: int seconds to store in memcache; default MEMCACHE_SECS.
    """
    memcache_entity_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    memcache_key = 'mwgpn_%s_%s_%s' % (cls.kind(), key_name, prop_name)
    entity = cls.get_or_insert(key_name)
    setattr(entity, prop_name, value)
    entity.put()
    entity_protobuf = db.model_to_protobuf(entity).SerializeToString()
    memcache.set(memcache_key, value, memcache_secs)
    memcache.set(memcache_entity_key, entity_protobuf, memcache_secs)

  @classmethod
  def MemcacheWrappedDelete(cls, key_name=None, entity=None):
    """Delete an entity by key name and clear Memcache.

    Note: This only clears the entity cache. If MemcacheWrappedGet()
    with a prop_name kwarg has been used, a separate cache will exist
    for that property. This function will not delete that memcache.
    TODO(user): If this function were actually used anywhere
    we should have prop_name=[] here so that users can delete prop_name
    caches too.

    Args:
      key_name: str, key name of entity to fetch
      entity: db.Model entity
    Raises:
      ValueError: when neither entity nor key_name are supplied
    """
    if entity:
      key_name = entity.key().name()
    elif key_name:
      entity = cls.get_by_key_name(key_name)
    else:
      raise ValueError

    if entity:
      entity.delete()
    memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    memcache.delete(memcache_key)


class BasePlistModel(BaseModel):
  """Base model which can easily store a utf-8 plist."""

  PLIST_LIB_CLASS = plist_lib.ApplePlist

  _plist = db.TextProperty()  # catalog/manifest/pkginfo plist file.

  def _ParsePlist(self):
    """Parses the self._plist XML into a plist_lib.ApplePlist object."""
    self._plist_obj = self.PLIST_LIB_CLASS(self._plist.encode('utf-8'))
    try:
      self._plist_obj.Parse()
    except plist_lib.PlistError, e:
      logging.exception('Error parsing self._plist: %s', str(e))
      self._plist_obj = None

  def _GetPlist(self):
    """Returns the _plist property encoded in utf-8."""
    if not hasattr(self, '_plist_obj'):
      if self._plist:
        self._ParsePlist()
      else:
        self._plist_obj = self.PLIST_LIB_CLASS('')

    return self._plist_obj

  def _SetPlist(self, plist):
    """Sets the _plist property.

    if plist is unicode, store as is.
    if plist is other, store it and attach assumption that encoding is utf-8.

    therefore, the setter only accepts unicode or utf-8 str (or ascii, which
    would fit inside utf-8)

    Args:
      plist: str or unicode XML plist.
    """
    if type(plist) is unicode:
      self._plist = db.Text(plist)
      self._ParsePlist()
    elif type(plist) is str:
      self._plist = db.Text(plist, encoding='utf-8')
      self._ParsePlist()
    else:
      self._plist_obj = plist
      self._plist = db.Text(self._plist_obj.GetXml())

  plist = property(_GetPlist, _SetPlist)

  def _GetPlistXml(self):
    """Returns the str plist."""
    return self._plist

  plist_xml = property(_GetPlistXml)

  def put(self, *args, **kwargs):
    """Put to Datastore.

    Args:
      args: list, optional, args to superclass put()
      kwargs: dict, optional, keyword args to superclass put()
    Returns:
      return value from superclass put()
    """
    if self.plist:
      self._plist = self.plist.GetXml()
    return super(BasePlistModel, self).put(*args, **kwargs)


class Computer(db.Model):
  """Computer model."""

  # All datetimes are UTC.
  active = db.BooleanProperty(default=True)  # automatically set property
  hostname = db.StringProperty()  # i.e. user-macbook.
  serial = db.StringProperty()  # str serial number of the computer.
  ip_address = db.StringProperty()  # str ip address of last connection
  uuid = db.StringProperty()  # OSX or Puppet UUID; undecided.
  runtype = db.StringProperty()  # Munki runtype. i.e. auto, custom, etc.
  preflight_datetime = db.DateTimeProperty()  # last preflight execution.
  postflight_datetime = db.DateTimeProperty()  # last postflight execution.
  last_notified_datetime = db.DateTimeProperty()  # last MSU.app popup.
  pkgs_to_install = db.StringListProperty()  # pkgs needed to be installed.
  all_apple_updates_installed = db.BooleanProperty()  # True=all installed.
  all_pkgs_installed = db.BooleanProperty()  # True=all installed, False=not.
  owner = db.StringProperty()  # i.e. foouser
  client_version = db.StringProperty()  # i.e. 0.6.0.759.0.
  os_version = db.StringProperty()  # i.e. 10.5.3, 10.6.1, etc.
  site = db.StringProperty()  # string site or campus name. i.e. NYC.
  # Simian track (i.e. Munki)
  track = db.StringProperty()  # i.e. stable, testing, unstable
  # Configuration track (i.e. Puppet)
  config_track = db.StringProperty()  # i.e. stable, testing, unstable
  # Connection dates and times.
  connection_dates = db.ListProperty(datetime.datetime)
  connection_datetimes = db.ListProperty(datetime.datetime)
  # Counts of connections on/off corp.
  connections_on_corp = db.IntegerProperty(default=0)
  connections_off_corp = db.IntegerProperty(default=0)
  last_on_corp_preflight_datetime = db.DateTimeProperty()
  uptime = db.FloatProperty()  # float seconds since last reboot.
  root_disk_free = db.IntegerProperty()  # int of bytes free on / partition.
  user_disk_free = db.IntegerProperty()  # int of bytes free in owner User dir.
  _user_settings = db.BlobProperty()
  user_settings_exist = db.BooleanProperty(default=False)
  # request logs to be uploaded, and notify email addresses saved here.
  # the property should contain a comma delimited list of email addresses.
  upload_logs_and_notify = db.StringProperty()
  # The number of preflight connections since the last successful postflight
  # connection. Resets to 0 when a postflight connection is posted.
  preflight_count_since_postflight = db.IntegerProperty(default=0)
  cert_fingerprint = db.StringProperty()

  def _GetUserSettings(self):
    """Returns the user setting dictionary, or None."""
    if self._user_settings:
      return util.Deserialize(self._user_settings)
    else:
      return None

  def _SetUserSettings(self, data):
    """Sets the user settings dictionary.

    Args:
      data: dictionary data to set to the user_settings, or None.
    """
    if not data:
      self.user_settings_exist = False
      self._user_settings = None
    else:
      self._user_settings = util.Serialize(data)
      self.user_settings_exist = True

  user_settings = property(_GetUserSettings, _SetUserSettings)

  @classmethod
  def AllActive(cls, keys_only=False):
    """Returns a query for all Computer entities that are active."""
    return cls.all(keys_only=keys_only).filter('active =', True)

  @classmethod
  def MarkInactive(cls):
    """Marks any inactive computers as such."""
    count = 0
    now = datetime.datetime.utcnow()
    earliest_active_date = now - datetime.timedelta(days=COMPUTER_ACTIVE_DAYS)
    query = cls.AllActive().filter('preflight_datetime <', earliest_active_date)
    gc.collect()
    while True:
      computers = query.fetch(500)
      if not computers:
        break
      for c in computers:
        c.active = False  # this isn't neccessary, but makes more obvious.
        c.put()
        count += 1
      cursor = str(query.cursor())
      del computers
      del query
      gc.collect()
      query = cls.AllActive().filter(
          'preflight_datetime <', earliest_active_date)
      query.with_cursor(cursor)
    return count

  def put(self, update_active=True):
    """Forcefully set active according to preflight_datetime."""
    if update_active:
      now = datetime.datetime.utcnow()
      earliest_active_date = now - datetime.timedelta(days=COMPUTER_ACTIVE_DAYS)
      if self.preflight_datetime:
        if self.preflight_datetime > earliest_active_date:
          self.active = True
        else:
          self.active = False
    super(Computer, self).put()


class ComputerClientBroken(db.Model):
  """Model to store broken client reports."""

  uuid = db.StringProperty()
  hostname = db.StringProperty()
  owner = db.StringProperty()
  reason = db.StringProperty()
  details = db.TextProperty()
  first_broken_datetime = db.DateTimeProperty(auto_now_add=True)
  broken_datetimes = db.ListProperty(datetime.datetime)
  fixed = db.BooleanProperty(default=False)
  serial = db.StringProperty()
  ticket_number = db.StringProperty()


class ComputerMSULog(db.Model):
  """Store MSU logs as state information.

  key = uuid_source_event
  """

  uuid = db.StringProperty()  # computer uuid
  source = db.StringProperty()  # "MSU", "user", ...
  event = db.StringProperty()  # "launched", "quit", ...
  user = db.StringProperty()  # user who MSU ran as -- may not be owner!
  desc = db.StringProperty()  # additional descriptive text
  mtime = db.DateTimeProperty()  # time of log


class ClientLogFile(db.Model):
  """Store client log files, like ManagedSoftwareUpdate.log.

  key = uuid + mtime
  """

  uuid = db.StringProperty()  # computer uuid
  name = db.StringProperty()  # log name
  mtime = db.DateTimeProperty(auto_now_add=True)
  log_file = properties.CompressedUtf8BlobProperty()


class Log(db.Model):
  """Base Log class to be extended for Simian logging."""

  # UTC datetime when the event occured.
  mtime = db.DateTimeProperty(auto_now_add=True)


class ClientLogBase(Log):
  """ClientLog model for all client interaction."""

  # denormalized OSX or Puppet UUID; undecided.
  uuid = db.StringProperty()
  computer = db.ReferenceProperty(Computer)


class ClientLog(ClientLogBase):
  """Model for generic client interaction (preflight exit, etc)."""

  action = db.StringProperty()  # short description of action.
  details = db.TextProperty()  # extended description.


class PreflightExitLog(ClientLogBase):
  """Model for preflight exit logging."""

  exit_reason = db.TextProperty()  # extended description.


class InstallLog(ClientLogBase):
  """Model for all client installs."""

  package = db.StringProperty()  # Firefox, Munkitools, etc.
  # TODO(user): change status to db.IntegerProperty(), convert all entities.
  status = db.StringProperty()  # return code; 0, 1, 2 etc.
  on_corp = db.BooleanProperty()  # True for install on corp, False otherwise.
  applesus = db.BooleanProperty(default=False)
  dl_kbytes_per_sec = db.IntegerProperty()
  duration_seconds = db.IntegerProperty()
  success = db.BooleanProperty()
  server_datetime = db.DateTimeProperty(auto_now_add=True)
  unattended = db.BooleanProperty()

  def IsSuccess(self):
    """Returns True if the install was a success, False otherwise."""
    # Most Adobe installers return 20 success. Yuck!
    return self.status in ['0', '20']

  def put(self):
    """Perform datastore put operation, forcefully setting success boolean."""
    self.success = self.IsSuccess()
    return super(InstallLog, self).put()


class AdminLogBase(Log):
  """AdminLogBase model for all admin interaction."""

  user = db.StringProperty()  # i.e. fooadminuser.


class AdminPackageLog(AdminLogBase, BasePlistModel):
  """AdminPackageLog model for all admin pkg interaction."""

  original_plist = db.TextProperty()
  action = db.StringProperty()  # i.e. upload, delete, etc.
  filename = db.StringProperty()
  catalogs = db.StringListProperty()
  manifests = db.StringListProperty()
  install_types = db.StringListProperty()

  def _GetPlistDiff(self):
    """Returns a generator of diff lines between original and new plist."""
    new_plist = self.plist.GetXml().splitlines()
    if not self.original_plist:
      return [{'type': 'diff_add', 'line': line} for line in new_plist]

    original_plist = self.original_plist.splitlines()
    new_plist = self.plist.GetXml().splitlines()
    diff = difflib.Differ().compare(original_plist, new_plist)

    lines = []
    if diff:
      re_add = re.compile("^\s*\+")
      re_sub = re.compile("^\s*\-")
      for line in diff:
        if re_add.match(line):
          linetype = 'diff_add'
        elif re_sub.match(line):
          linetype = 'diff_sub'
        else:
          linetype = 'diff_none'
        lines.append({'type': linetype, 'line': line})

    omitting = False
    for i, line in enumerate(lines):
      if i > 1 and i < len(lines)-2:
        # A line is "omittable" if it's at least 2 lines away from the start,
        # end or an edited line.
        is_omit = all([l['type'] == 'diff_none' for l in lines[i-2:i+3]])
        if is_omit and not omitting:
          line['start_omitting'] = True
          omitting = True
      if omitting:
        not_omit = any([l['type'] != 'diff_none' for l in lines[i:i+3]])
        if i > len(lines)-3 or not_omit:
          line['end_omitting'] = True
          omitting = False

    return lines

  plist_diff = property(_GetPlistDiff)


class AdminPackageProposalLog(AdminPackageLog):
  """AdminPackageLog model for all admin pkg interaction."""

  approver = db.StringProperty()


class AdminAppleSUSProductLog(AdminLogBase):
  """Model to log all admin Apple SUS Product changes."""

  product_id = db.StringProperty()
  action = db.StringProperty()
  tracks = db.StringListProperty()

  @classmethod
  def Log(cls, products, action):
    """Puts batches of product changes to AdminAppleSUSProductLog.

    Args:
      products: list of or single models.AppleSUSProduct entity.
      action: str, description of the change taking place to the batch.
    """
    # Support products being a single product entity.
    if not isinstance(products, (list, tuple)):
      products = (products,)

    to_put = []
    for p in products:
      log = cls(product_id=p.product_id, action=action, tracks=p.tracks)
      log.mtime = datetime.datetime.utcnow()
      to_put.append(log)
    # Put all log entities together.
    gae_util.BatchDatastoreOp(db.put, to_put)




class KeyValueCache(BaseModel):
  """Model for a generic key value pair storage."""

  text_value = db.TextProperty()
  blob_value = db.BlobProperty()
  mtime = db.DateTimeProperty(auto_now=True)

  @classmethod
  def IpInList(cls, key_name, ip):
    """Check whether IP is in serialized IP/mask list in key_name.

    The KeyValueCache entity at key_name is expected to have a text_value
    which is in util.Serialize() form. The deserialized structure looks like

    [ "200.0.0.0/24",
      "10.0.0.0/8",
      etc ...
    ]

    Note that this function is not IPv6 safe and will always return False
    if the input ip is IPv6 format.

    Args:
      key_name: str, like 'auth_bad_ip_blocks'
      ip: str, like '127.0.0.1'
    Returns:
      True if the ip is inside a mask in the list, False if not
    """
    if not ip:
      return False  # lenient response

    # TODO(user): Once the underlying util.Ip* methods support ipv6
    # this method can go away. Until then, this stops all of the churn
    # and exits early.
    if ip.find(':') > -1:  # ipv6
      return False

    try:
      ip_blocks_str = cls.MemcacheWrappedGet(key_name, 'text_value')
      if not ip_blocks_str:
        return False
      ip_blocks = util.Deserialize(ip_blocks_str)
    except (util.DeserializeError, db.Error):
      logging.exception('IpInList(%s)', ip)
      return False  # lenient response

    # Note: The method below, parsing a serialized list of networks
    # expressed as strings, might seem silly. But the total time to
    # deserialize and translate the strings back into IP network/mask
    # integers is actually faster than storing them already split, e.g. a
    # list of 2 item lists (network,mask). Apparently JSON isn't as
    # efficient at parsing ints or nested lists.
    #
    # (pickle is 2X+ faster but not secure & deprecated inside util module)

    ip_int = ipcalc.IpToInt(ip)

    for ip_mask_str in ip_blocks:
      ip_mask = ipcalc.IpMaskToInts(ip_mask_str)
      if (ip_int & ip_mask[1]) == ip_mask[0]:
        return True

    return False

  @classmethod
  def GetSerializedItem(cls, key):
    """Returns the deserialized value of a serialized cache."""
    entity = cls.MemcacheWrappedGet(key)
    if entity and entity.blob_value:
      return util.Deserialize(entity.blob_value), entity.mtime
    else:
      return {}, None

  @classmethod
  def SetSerializedItem(cls, key, value):
    """Serializes a value and caches it to an entity with a given key.

    Args:
      key: str, key_name for the ReportsCache entity.
      value: any, a value of any kind to serialize and cache.
    """
    value = util.Serialize(value)
    cls.MemcacheWrappedSet(key, 'blob_value', value)

  @classmethod
  def GetItem(cls, name):
    entity = cls.MemcacheWrappedGet(name)
    if entity:
      return entity.text_value, entity.mtime
    else:
      return None, None

  @classmethod
  def SetItem(cls, name, value):
    return cls.MemcacheWrappedSet(name, 'text_value', value)


class ReportsCache(KeyValueCache):
  """Model for various reports data caching."""

  _SUMMARY_KEY = 'summary'
  _INSTALL_COUNTS_KEY = 'install_counts'
  _TRENDING_INSTALLS_KEY = 'trending_installs_%d_hours'
  _PENDING_COUNTS_KEY = 'pending_counts'
  _MSU_USER_SUMMARY_KEY = 'msu_user_summary'

  int_value = db.IntegerProperty()

  # TODO(user): migrate reports cache to properties.SerializedProperty()

  @classmethod
  def GetStatsSummary(cls):
    """Returns tuples (stats summary dictionary, datetime) from Datastore."""
    return cls.GetSerializedItem(cls._SUMMARY_KEY)

  @classmethod
  def SetStatsSummary(cls, d):
    """Sets a the stats summary dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    return cls.SetSerializedItem(cls._SUMMARY_KEY, d)

  @classmethod
  def GetInstallCounts(cls):
    """Returns tuple (install counts dict, datetime) from Datastore."""
    return cls.GetSerializedItem(cls._INSTALL_COUNTS_KEY)

  @classmethod
  def SetInstallCounts(cls, d):
    """Sets a the install counts dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    return cls.SetSerializedItem(cls._INSTALL_COUNTS_KEY, d)

  @classmethod
  def GetTrendingInstalls(cls, since_hours):
    key = cls._TRENDING_INSTALLS_KEY % since_hours
    return cls.GetSerializedItem(key)

  @classmethod
  def SetTrendingInstalls(cls, since_hours, d):
    key = cls._TRENDING_INSTALLS_KEY % since_hours
    return cls.SetSerializedItem(key, d)

  @classmethod
  def GetPendingCounts(cls):
    """Returns tuple (pending counts dict, datetime) from Datastore."""
    return cls.GetSerializedItem(cls._PENDING_COUNTS_KEY)

  @classmethod
  def SetPendingCounts(cls, d):
    """Sets a the pending counts dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    return cls.SetSerializedItem(cls._PENDING_COUNTS_KEY, d)

  @classmethod
  def _GetMsuUserSummaryKey(cls, since, tmp):
    if since is not None:
      since = '_since_%s_' % since
    else:
      since = ''
    return '%s%s%s' % (cls._MSU_USER_SUMMARY_KEY, since, tmp * '_tmp')

  @classmethod
  def SetMsuUserSummary(cls, d, since=None, tmp=False):
    """Sets the msu user summary dictionary to Datstore.

    Args:
      d: dict of summary data.
      since: str, since when
      tmp: bool, default False, retrieve tmp summary (in process of
        calculation)
    """
    key = cls._GetMsuUserSummaryKey(since, tmp)
    return cls.SetSerializedItem(key, d)

  @classmethod
  def GetMsuUserSummary(cls, since, tmp=False):
    """Gets the MSU user summary dictionary from Datastore.

    Args:
      since: str, summary since date
    Returns:
      (dict of summary data, datetime mtime) or None if no summary
    """
    key = cls._GetMsuUserSummaryKey(since, tmp)
    return cls.GetSerializedItem(key)

  @classmethod
  def DeleteMsuUserSummary(cls, since, tmp=False):
    """Deletes the MSU user summary entity from Datastore.

    Args:
      since: str, summary since date
    """
    key = cls._GetMsuUserSummaryKey(since, tmp)
    entity = cls.get_by_key_name(key)
    if not entity:
      return
    entity.delete()


# Munki ########################################################################


class AuthSession(db.Model):
  """Auth sessions.

  key = session_id
  """

  data = db.StringProperty()
  mtime = db.DateTimeProperty()
  state = db.StringProperty()
  uuid = db.StringProperty()
  level = db.IntegerProperty(default=0)


class BaseCompressedMunkiModel(BaseModel):
  """Base class for Munki related models."""

  name = db.StringProperty()
  mtime = db.DateTimeProperty(auto_now=True)
  # catalog/manifest/pkginfo plist file.
  plist = properties.CompressedUtf8BlobProperty()


class AppleSUSCatalog(BaseCompressedMunkiModel):
  """Apple Software Update Service Catalog."""

  last_modified_header = db.StringProperty()


class AppleSUSProduct(BaseModel):
  """Apple Software Update Service products."""

  product_id = db.StringProperty()
  name = db.StringProperty()
  version = db.StringProperty()
  description = db.TextProperty()
  restart_required = db.BooleanProperty()
  force_install_after_date = db.DateTimeProperty()
  apple_mtime = db.DateTimeProperty()
  tracks = db.StringListProperty()
  mtime = db.DateTimeProperty(auto_now=True)
  # If manual_override, then auto-promotion will not occur.
  manual_override = db.BooleanProperty(default=False)
  # If unattended, then unattended installation will proceed.
  unattended = db.BooleanProperty(default=False)
  unattended_uninstall = db.BooleanProperty(default=False)
  # If deprecated, then the product is entirely hidden and unused.
  deprecated = db.BooleanProperty(default=False)
  # Package download URLs.
  package_urls = db.StringListProperty()

  @classmethod
  def AllActive(cls, keys_only=False):
    """Returns a query for all Computer entities that are active."""
    return cls.all(keys_only=keys_only).filter('deprecated =', False)

  def _GetPkginfoPlist(self):
    """Returns a pkginfo plist for an Apple Update Product."""
    d = {
        'installer_type': 'apple_update_metadata',
        'name': self.product_id,
    }
    if self.unattended:
      d['unattended_install'] = self.unattended
    if self.unattended_uninstall:
      d['unattended_uninstall'] = self.unattended_uninstall
    if self.force_install_after_date:
      d['force_install_after_date'] = self.force_install_after_date
    d['version'] = '1.0'  # TODO(user): find out if this is needed.

    plist = plist_lib.ApplePlist()
    plist.SetContents(d)
    return plist

  plist = property(_GetPkginfoPlist)

  def _GetForceInstallAfterDateStr(self):
    """Returns the force_install_after_date property in Munki catalog format."""
    if self.force_install_after_date:
      return self.force_install_after_date.strftime('%Y-%m-%dT%H:%M:%SZ')

  def _SetForceInstallAfterDateStr(self, str_dt):
    """Sets the force_install_after_date property from a string."""
    try:
      dt = datetime.datetime.strptime(str_dt, '%Y-%m-%d %H:%M')
    except ValueError:
      try:
        dt = datetime.datetime.strptime('%s 13:00' % (str_dt), '%Y-%m-%d %H:%M')
      except ValueError:
        raise
    self.force_install_after_date = dt

  force_install_after_date_str = property(
      _GetForceInstallAfterDateStr, _SetForceInstallAfterDateStr)

  def _GetMunkiName(self):
    """Returns a PackageName-Version formatted name of the product."""
    return '%s-%s' % (self.name, self.version)

  munki_name = property(_GetMunkiName)


class Tag(BaseModel):
  """A generic string tag that references a list of db.Key objects."""

  ALL_TAGS_MEMCACHE_KEY = 'all_tags'

  user = db.UserProperty(auto_current_user=True)
  mrtime = db.DateTimeProperty(auto_now=True)
  keys = db.ListProperty(db.Key)

  def put(self, *args, **kwargs):
    """Ensure tags memcache entries are purged when a new one is created."""
    memcache.delete(self.ALL_TAGS_MEMCACHE_KEY)
    return super(Tag, self).put(*args, **kwargs)

  def delete(self, *args, **kwargs):
    """Ensure tags memcache entries are purged when one is delete."""
    # TODO(user): extend BaseModel so such memcache cleanup is reusable.
    memcache.delete(self.ALL_TAGS_MEMCACHE_KEY)
    return super(Tag, self).delete(*args, **kwargs)

  @classmethod
  def GetAllTagNames(cls):
    """Returns a list of all tag names."""
    tags = memcache.get(cls.ALL_TAGS_MEMCACHE_KEY)
    if not tags:
      tags = [key.name() for key in cls.all(keys_only=True)]
      tags = sorted(tags, key=unicode.lower)
      memcache.set(cls.ALL_TAGS_MEMCACHE_KEY, tags)
    return tags

  @classmethod
  def GetAllTagNamesForKey(cls, key):
    """Returns a list of all tag names for a given db.Key."""
    return [k.name() for k in
            cls.all(keys_only=True).filter('keys =', key)]

  @classmethod
  def GetAllTagNamesForEntity(cls, entity):
    """Returns a list of all tag names."""
    return cls.GetAllTagNamesForKey(entity.key())


class Group(BaseModel):
  """A generic string group that references a list of string users."""
  ALL_GROUPS_MEMCACHE_KEY = 'all_groups'

  modifier = db.UserProperty(auto_current_user=True)
  mrtime = db.DateTimeProperty(auto_now=True)
  users = db.StringListProperty()

  def put(self, *args, **kwargs):
    """Ensure groups memcache entries are purged when a new one is created."""
    memcache.delete(self.ALL_GROUPS_MEMCACHE_KEY)
    return super(Group, self).put(*args, **kwargs)

  def delete(self, *args, **kwargs):
    """Ensure groups memcache entries are purged when one is delete."""
    memcache.delete(self.ALL_GROUPS_MEMCACHE_KEY)
    return super(Group, self).delete(*args, **kwargs)

  @classmethod
  def GetAllGroupNames(cls):
    """Returns a list of all group names."""
    groups = memcache.get(cls.ALL_GROUPS_MEMCACHE_KEY)
    if not groups:
      groups = [key.name() for key in cls.all(keys_only=True)]
      groups = sorted(groups, key=unicode.lower)
      memcache.set(cls.ALL_GROUPS_MEMCACHE_KEY, groups)
    return groups

  @classmethod
  def GetAllGroupNamesForUser(cls, user):
    """Returns a list of all group names for a given string user."""
    return [k.name() for k in
            cls.all(keys_only=True).filter('users =', user)]


class BaseManifestModification(BaseModel):
  """Manifest modifications for dynamic manifest generation."""

  enabled = db.BooleanProperty(default=True)
  install_types = db.StringListProperty()  # ['managed_installs']
  # Value to be added or removed from the install_type above.
  value = db.StringProperty()  # fooinstallname. -fooinstallname to remove it.
  manifests = db.StringListProperty()  # ['unstable', 'testing']
  # Automatic properties to record who made the mod and when.
  mtime = db.DateTimeProperty(auto_now_add=True)
  user = db.UserProperty()

  def Serialize(self):
    """Returns a serialized string representation of the entity instance."""
    d = {}
    for p in self.properties():
      d[p] = getattr(self, p)
      if p in ['mtime', 'user']:
        d[p] = str(d[p])
    return util.Serialize(d)

  def _GetTarget(self):
    """Returns the modification target property, defined by subclasses."""
    if not hasattr(self, 'TARGET_PROPERTY_NAME'):
      raise NotImplementedError
    return getattr(self, self.TARGET_PROPERTY_NAME)

  def _SetTarget(self, target):
    """Sets the modification target property, defined by subclasses."""
    if not hasattr(self, 'TARGET_PROPERTY_NAME'):
      raise NotImplementedError
    setattr(self, self.TARGET_PROPERTY_NAME, target)

  target = property(_GetTarget, _SetTarget)

  @classmethod
  def GenerateInstance(cls, mod_type, target,
                       munki_pkg_name, remove=False, **kwargs):
    """Returns a model instance for the passed mod_type.

    Args:
      mod_type: str, modification type like 'site', 'owner', etc.
      target: str, modification target value, like 'foouser', or 'foouuid'.
      munki_pkg_name: str, name of the munki package to inject, like Firefox.
      remove: if True, will remove package from manifest instead of adding it.
      **kwargs: any other properties to set on the model instance.
    Returns:
      A model instance with key_name, value and the model-specific mod key value
      properties already set.
    Raises:
      ValueError: if a manifest mod_type is unknown
    """
    key_name = '%s##%s' % (target, munki_pkg_name)
    model = MANIFEST_MOD_MODELS.get(mod_type, None)
    if not model:
      raise ValueError
    m = model(key_name=key_name)
    m.target = target
    m.value = munki_pkg_name
    if remove:
      m.value = '-' + m.value
    for kw in kwargs:
      setattr(m, kw, kwargs[kw])
    return m

  @classmethod
  def ResetModMemcache(cls, mod_type, target):
    """Clear the memcache associated with this modification type.

    Args:
      mod_type: str, modification type like 'site', 'owner', etc.
      target: str, modification target value, like 'foouser', or 'foouuid'.
    Raises:
      ValueError: if a manifest mod_type is unknown
    """
    model = MANIFEST_MOD_MODELS.get(mod_type, None)
    if not model:
      raise ValueError

    model.DeleteMemcacheWrappedGetAllFilter((('%s =' % mod_type, target),))


class SiteManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by site."""

  TARGET_PROPERTY_NAME = 'site'

  site = db.StringProperty()  # NYC, MTV, etc.


class OSVersionManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by OS version."""

  TARGET_PROPERTY_NAME = 'os_version'

  os_version = db.StringProperty()  # 10.6.5


class OwnerManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by owner."""

  TARGET_PROPERTY_NAME = 'owner'

  owner = db.StringProperty()  # foouser


class UuidManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by computer."""

  TARGET_PROPERTY_NAME = 'uuid'

  uuid = db.StringProperty()  # Computer.uuid format


class TagManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by a tag."""

  TARGET_PROPERTY_NAME = 'tag_key_name'

  tag_key_name = db.StringProperty()  # Tag Model key_name.


class GroupManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by user group."""

  TARGET_PROPERTY_NAME = 'group_key_name'

  group_key_name = db.StringProperty()  # Group Model key_name.


MANIFEST_MOD_MODELS = {
    'owner': OwnerManifestModification,
    'uuid': UuidManifestModification,
    'site': SiteManifestModification,
    'os_version': OSVersionManifestModification,
    'tag': TagManifestModification,
    'group': GroupManifestModification,
}


class PackageAlias(BaseModel):
  """Maps an alias to a Munki package name.

  Note: PackageAlias key_name should be the alias name.
  """

  munki_pkg_name = db.StringProperty()
  enabled = db.BooleanProperty(default=True)

  @classmethod
  def ResolvePackageName(cls, pkg_alias):
    """Returns a package name for a given alias, or None if alias was not found.

    Args:
      pkg_alias: str package alias.
    Returns:
      str package name, or None if the pkg_alias was not found.
    """
    entity = cls.MemcacheWrappedGet(pkg_alias)
    if not entity:
      # TODO(user): email Simian admins ??
      logging.error('Unknown pkg_alias requested: %s', pkg_alias)
    elif entity.enabled and entity.munki_pkg_name:
      return entity.munki_pkg_name
    return None


class FirstClientConnection(BaseModel):
  """Model to keep track of new clients and whether they've been emailed."""

  mtime = db.DateTimeProperty(auto_now_add=True)
  computer = db.ReferenceProperty(Computer)
  owner = db.StringProperty()
  hostname = db.StringProperty()
  emailed = db.DateTimeProperty()
  site = db.StringProperty()
