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

"""App Engine Models for Simian web application."""



import datetime
import gc
import logging
from google.appengine import runtime
from google.appengine.ext import db
from google.appengine.ext import deferred
from google.appengine.api import memcache
from google.appengine.runtime import apiproxy_errors
from simian.mac import zip
from simian.mac import common
from simian.mac.common import util
from simian.mac.common import gae_util
from simian.mac.munki import plist as plist_lib


class Error(Exception):
  """Class for domain exceptions."""


class InvalidArgumentsError(Error):
  """Invalid arguments were passed."""


# Simian #####################################################################

COMPUTER_ACTIVE_DAYS = 30


class CompressedUtf8BlobProperty(db.BlobProperty):
  """BlobProperty class that compresses/decompresses seamlessly on get/set.

  This Property is compressed on every __set__ and decompressed on every __get__
  operation. This should be taken into consideration when performing certain
  operations, such as slicing.
  """

  # pylint: disable-msg=C6409
  def get_value_for_datastore(self, model_instance):
    """Compresses the blob value on it's way to Datastore."""
    value = super(CompressedUtf8BlobProperty, self).get_value_for_datastore(
        model_instance)
    if value is None:
      self.length = 0
    else:
      self.length = len(value)
    return db.Blob(zip.CompressedText(value, encoding='utf-8').Compressed())

  # pylint: disable-msg=C6409
  def __get__(self, model_instance, model_class):
    """Decompresses the blob value when the property is accessed."""
    value = super(CompressedUtf8BlobProperty, self).__get__(
        model_instance, model_class)
    if value is self:
      return self
    return unicode(zip.CompressedText(value, encoding='utf-8')).encode('utf-8')

  # pylint: disable-msg=C6409
  def __set__(self, model_instance, value):
    """Compresses the value when the property is set."""
    if not value:
      self.length = 0
      super(CompressedUtf8BlobProperty, self).__set__(model_instance, value)
    else:
      self.length = len(value)
      value = zip.CompressedText(value, encoding='utf-8').Compressed()
      super(CompressedUtf8BlobProperty, self).__set__(model_instance, value)

  # pylint: disable-msg=C6409
  def __len__(self):
    """Returns the length of the uncompressed blob data."""
    return self.length


class BaseModel(db.Model):
  """Abstract base model with useful generic methods."""

  @classmethod
  def MemcacheAddAutoUpdateTask(cls, func, *args, **kwargs):
    """Sets a memcache auto update task.

    Args:
      func: str, like "MemcacheWrappedSet"
      args: list, optional, arguments to function
      kwargs: dict, optional, keyword arguments to function
    """
    if not hasattr(cls, func) or not callable(getattr(cls, func)):
      raise ValueError(func)
    if not hasattr(cls, '_memcache_auto_update_tasks'):
      cls._memcache_auto_update_tasks = []
    cls._memcache_auto_update_tasks.append((func, args, kwargs))

  @classmethod
  def MemcacheAutoUpdate(cls, _deferred=False):
    """Run all memcache auto updates.

    Args:
      _deferred: bool, whether this function has been deferred
    """
    if not getattr(cls, '_memcache_auto_update_tasks', None):
      return

    if not _deferred:
      deferred.defer(cls.MemcacheAutoUpdate, _deferred=True, _countdown=10)
      return

    for func, args, kwargs in getattr(cls, '_memcache_auto_update_tasks', []):
      getattr(cls, func)(*args, **kwargs)

  @classmethod
  def ResetMemcacheWrap(cls, key_name, memcache_secs=300):
    """Deletes a cached entity from memcache.

    Args:
      key_name: str key name of the entity to fetch.
      memcache_secs: int seconds to store in memcache; default 300s, so 5mins.
    """
    memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    entity = cls.get_by_key_name(key_name)
    memcache.set(memcache_key, entity, memcache_secs)

  @classmethod
  def MemcacheWrappedGet(cls, key_name, prop_name=None, memcache_secs=300):
    """Fetches an entity by key name from model wrapped by Memcache.

    Args:
      key_name: str key name of the entity to fetch.
      prop_name: optional property name to return the value for instead of
        returning the entire entity.
      memcache_secs: int seconds to store in memcache; default 300s, so 5mins.
    Returns:
      If prop_name==None returns the db.Model entity, otherwise only returns
      the property value.
    """
    memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    entity = memcache.get(memcache_key)
    if entity is None:
      entity = cls.get_by_key_name(key_name)
      if not entity:
        return
      try:
        memcache.set(memcache_key, entity, memcache_secs)
      except ValueError, e:
        logging.warning(
            'MemcacheWrappedGet failed to set %s: %s', memcache_key, str(e))

    if prop_name:
      return getattr(entity, prop_name)
    return entity

  @classmethod
  def MemcacheWrappedGetAllFilter(
      cls, filters=(), limit=1000, memcache_secs=300):
    """Fetches all entities for a filter set, wrapped by Memcache.

    Args:
      filters: tuple, optional, filter arguments, e.g.
        ( ( "foo =", True ),
          ( "zoo =", 1 ), ),
      limit: int, number of rows to fetch
      memcache_secs: int seconds to store in memcache; default 300s, so 5mins.
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
  def MemcacheWrappedSet(cls, key_name, prop_name, value, memcache_secs=300):
    """Sets an entity by key name and property wrapped by Memcache.

    Args:
      key_name: str, key name of entity to fetch
      prop_name: str, property name to set with value
      value: object, value to set
      memcache_secs: int, default 300, seconds to store in memcache.
    """
    memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    entity = cls.get_or_insert(key_name)
    setattr(entity, prop_name, value)
    entity.put()
    memcache.set(memcache_key, entity, memcache_secs)

  @classmethod
  def MemcacheWrappedDelete(cls, key_name=None, entity=None):
    """Delete an entity by key name and clear Memcache.

    Args:
      key_name: str, key name of entity to fetch
      entity: db.Model entity.
    """
    if entity:
      key_name = entity.key().name()
    elif key_name:
      entity = cls.get_by_key_name(key_name)
    else:
      raise ValueError

    entity.delete()
    memcache_key = 'mwg_%s_%s' % (cls.kind(), key_name)
    memcache.delete(memcache_key)

  @classmethod
  def MemcacheWrappedPropMapGenerate(
      cls, prop_name, defer_if_locked=False, memcache_secs=300):
    """Cache model keys in a memcache container where prop_name == value.

    Args:
      key_name: str, key name of entity
      prop_name: str, property name to set with value
      defer_if_locked: bool, default False, if True, defer to a
        background task if the prop map generation is currently locked.
        if False and locked, return without doing any work, letting the current
        generator finish without producing additional work.
      memcache_secs: int, default 300, seconds to store in memcache.
    """
    lock_name = 'mwpm_%s_%s' % (cls.kind(), prop_name)
    if not gae_util.ObtainLock(lock_name):
      if defer_if_locked:
        logging.info(
            'MemcacheWrappedPropMapGenerate: Could not obtain lock %s',
            lock_name)
        deferred.defer(cls.MemcacheWrappedPropMapGenerate,
          prop_name,
          defer_if_locked=defer_if_locked,
          memcache_secs=memcache_secs,
          _countdown=10)
      return

    map_data = {}
    try:
      query = cls.all()
      for entity in query:
        a = getattr(entity, prop_name, None)
        if a:
          map_data.setdefault(a, []).append(entity.key())
    except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
      gae_util.ReleaseLock(lock_name)
      return
    memcache_key = 'mwpm_%s_%s' % (cls.kind(), prop_name)
    memcache.set(memcache_key, map_data, memcache_secs)
    gae_util.ReleaseLock(lock_name)

  @classmethod
  def MemcacheWrappedPropMapGetAll(cls, prop_name, value):
    """Memcache wrapped get of all entities where prop_name==value.

    All the entities in the model are cached by prop_name to speed lookups.

    Args:
      prop_name: str, property name to search.
      value: str, value of property name to look for.
    Returns:
      array, [ list of entities where prop_name == value ]
    Raises:
      KeyError: if no prop_name==value entities exist.
    """
    memcache_key = 'mwpm_%s_%s' % (cls.kind(), prop_name)
    map_data = memcache.get(memcache_key)
    entities = None

    # Explictly check for None, as the map may be empty.
    if map_data is None:
      # TODO(user): since this isn't locked before deferral, every 5 mins we
      #   have tons of deferred calls until the map is regenerated. think about
      #   locking before calling deferred.
      try:
        deferred.defer(cls.MemcacheWrappedPropMapGenerate, prop_name)
      except deferred.taskqueue.TransientError:
        logging.exception(
            'TransientError deferring MemcacheWrappedPropMapGenerate.')
      entities = cls.MemcacheWrappedGetAllFilter(
          (('%s =' % prop_name, value),))
    elif value in map_data:
      entities = cls.get(map_data[value])

    if entities:
      return entities
    else:
      raise KeyError

  def put(self, *args, **kwargs):
    """Perform datastore put operation.

    Args:
      args: list, optional, args to superclass put()
      kwargs: dict, optional, keyword args to superclass put()
    Returns:
      return value from superclass put()
    """
    r = super(BaseModel, self).put(*args, **kwargs)
    self.MemcacheAutoUpdate()
    return r


class BasePlistModel(BaseModel):
  """Base model which can easy store a utf-8 plist."""

  _plist = db.TextProperty()  # catalog/manifest/pkginfo plist file.

  def _GetPlist(self):
    """Returns the _plist property encoded in utf-8."""
    return self._plist.encode('utf-8')

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
    else:
      self._plist = db.Text(plist, encoding='utf-8')

  plist = property(_GetPlist, _SetPlist)


class Computer(db.Model):
  """Computer model."""

  # All datetimes are UTC.
  active = db.BooleanProperty(default=True)  # automatically set property
  hostname = db.StringProperty()  # i.e. user-macbook.
  serial = db.StringProperty()  # str serial number of the computer.
  ip_address = db.StringProperty()  # str ip address of last connection
  uuid = db.StringProperty()  # OSX or Puppet UUID; undecided.
  global_uuid = db.StringProperty()  # global, platform-independent UUID
  preflight_datetime = db.DateTimeProperty()  # last preflight execution.
  postflight_datetime = db.DateTimeProperty()  # last postflight execution.
  last_notified_datetime = db.DateTimeProperty()  # last MSU.app popup.
  pkgs_to_install = db.StringListProperty()  # pkgs needed to be installed.
  all_pkgs_installed = db.BooleanProperty()  # True=all installed, False=not.
  owner = db.StringProperty()  # i.e. foouser
  client_version = db.StringProperty()  # i.e. 0.6.0.759.0.
  os_version = db.StringProperty()  # i.e. 10.5.3, 10.6.1, etc.
  site = db.StringProperty()  # string site or campus name. i.e. NYC.
  office = db.StringProperty()  # string office name. i.e. US-NYC-FOO.
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
      del(computers)
      del(query)
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
  details = db.TextProperty()
  first_broken_datetime = db.DateTimeProperty(auto_now_add=True)
  broken_datetimes = db.ListProperty(datetime.datetime)
  fixed = db.BooleanProperty(default=False)
  ticket_number = db.StringProperty()


class ComputerLostStolen(db.Model):
  """Model to store reports about lost/stolen machines."""

  uuid = db.StringProperty()
  computer = db.ReferenceProperty(Computer)
  connections = db.StringListProperty()
  lost_stolen_datetime = db.DateTimeProperty(auto_now_add=True)
  mtime = db.DateTimeProperty()

  @classmethod
  def _GetUuids(cls, force_refresh=False):
    """Gets the lost/stolen UUID dictionary from memcache or Datastore.

    Args:
      force_refresh: boolean, when True it repopulates memcache from Datastore.
    """
    uuids = memcache.get('loststolen_uuids')
    if not uuids or force_refresh:
      uuids = {}
      for key in cls.all(keys_only=True):
        uuids[key.name()] = True
      memcache.set('loststolen_uuids', uuids)
    return uuids

  @classmethod
  def IsLostStolen(cls, uuid):
    """Returns True if the given str UUID is lost/stolen, False otherwise."""
    return uuid in cls._GetUuids()

  @classmethod
  def SetLostStolen(cls, uuid):
    """Sets a UUID as lost/stolen, and refreshes the lost/stolen UUID cache."""
    if cls.get_by_key_name(uuid):
      logging.warning('UUID already set as lost/stolen: %s', uuid)
      return  # do nothing; the UUID is already set as lost/stolen.
    computer = Computer.get_by_key_name(uuid)
    ls = cls(key_name=computer.uuid, computer=computer, uuid=uuid)
    ls.put()
    cls._GetUuids(force_refresh=True)

  @classmethod
  def LogLostStolenConnection(cls, computer, ip_address):
    """Logs a connection from a lost/stolen computer."""
    ls = cls.get_or_insert(computer.uuid)
    ls.computer = computer
    ls.uuid = computer.uuid
    now = datetime.datetime.utcnow()
    ls.mtime = now
    ls.connections.append('%s from %s' % (now, ip_address))
    ls.put()


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
  log_file = CompressedUtf8BlobProperty()


class Log(db.Model):
  """Base Log class to be extended for Simian logging."""

  # UTC datetime when the event occured.
  mtime = db.DateTimeProperty()

  def put(self):
    """If a log mtime was not set, automatically set it to now in UTC.

    Note: auto_now_add=True is not ideal as then clients can't report logs that
          were written in the past.
    """
    if not self.mtime:
      self.mtime = datetime.datetime.utcnow()
    super(Log, self).put()


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
  duration_seconds = db.IntegerProperty()
  success = db.BooleanProperty()

  def IsSuccess(self):
    """Returns True if the install was a success, False otherwise."""
    return self.status == '0'

  def put(self):
    """Perform datastore put operation, forcefully setting success boolean."""
    self.success = self.IsSuccess()
    return super(InstallLog, self).put()


class AdminLogBase(Log):
  """AdminLogBase model for all admin interaction."""

  user = db.StringProperty()  # i.e. fooadminuser.


class AdminPackageLog(AdminLogBase, BasePlistModel):
  """AdminPackageLog model for all admin pkg interaction."""

  action = db.StringProperty()  # i.e. upload, delete, etc.
  filename = db.StringProperty()
  catalogs = db.StringListProperty()
  manifests = db.StringListProperty()
  install_types = db.StringListProperty()


class AdminAppleSUSProductLog(AdminLogBase):
  """Model to log all admin Apple SUS Product changes."""

  product_id = db.StringProperty()
  action = db.StringProperty()
  tracks = db.StringListProperty()


class KeyValueCache(BaseModel):
  """Model for a generic key value pair storage."""

  text_value = db.TextProperty()
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

    if ip.find(':') > -1:  # ipv6
      return False

    try:
      ip_blocks_str = cls.MemcacheWrappedGet(key_name, 'text_value')
      if not ip_blocks_str:
        return False
      ip_blocks = util.Deserialize(ip_blocks_str)
    except (util.DeserializeError, db.Error), e:
      logging.exception('IpInList(%s)' % ip)
      return False  # lenient response

    # Note: The method below, parsing a serialized list of networks
    # expressed as strings, might seem silly. But the total time to
    # deserialize and translate the strings back into IP network/mask
    # integers is actually faster than storing them already split, e.g. a
    # list of 2 item lists (network,mask). Apparently JSON isn't as
    # efficient at parsing ints or nested lists.
    #
    # (pickle is 2X+ faster but not secure & deprecated inside util module)

    ip_int = util.IpToInt(ip)

    for ip_mask_str in ip_blocks:
      ip_mask = util.IpMaskToInts(ip_mask_str)
      if (ip_int & ip_mask[1]) == ip_mask[0]:
        return True

    return False


class ReportsCache(KeyValueCache):
  """Model for various reports data caching."""

  _SUMMARY_KEY = 'summary'
  _INSTALL_COUNTS_KEY = 'install_counts'
  _PENDING_COUNTS_KEY = 'pending_counts'
  _MSU_USER_SUMMARY_KEY = 'msu_user_summary'
  _TRACK_PREFIX = 'client_count__'
  _ALL_SUFFIX = '__ALL'

  int_value = db.IntegerProperty()
  blob_value = db.BlobProperty()

  @classmethod
  def _GetClientCountKey(cls, count_type, count_name):
    """Gets a client count key for given kwarg."""
    if not count_type and not count_name:
      count_type = ''
      count_name = cls._ALL_SUFFIX
    elif not count_type or not count_name:
      raise InvalidArgumentsError(
          'count_type and count_name must be both None or set together.')
    return '%s%s__%s' % (cls._TRACK_PREFIX, count_type, count_name)

  @classmethod
  def GetClientCount(cls, count_type=None, count_name=None):
    """Gets an integer client count from Datastore for a given track.

    Args:
      count_type: str type of count, like "track" or "day_actives".
      count_name: str name of count, like "stable" or "7".
    Returns:
      Integer count of clients.
    """
    key = cls._GetClientCountKey(count_type, count_name)
    return cls.get_by_key_name(key).int_value

  @classmethod
  def SetClientCount(cls, count, count_type=None, count_name=None):
    """Sets a track integer count.

    Args:
      count: integer number of clients.
      count_type: str type of count, like "track" or "day_actives".
      count_name: str name of count, like "stable" or "7".
    """
    key = cls._GetClientCountKey(count_type, count_name)
    cls(key_name=key, int_value=count).put()

  @classmethod
  def GetStatsSummary(cls):
    """Returns tuples (stats summary dictionary, datetime) from Datastore."""
    entity = cls.get_by_key_name(cls._SUMMARY_KEY)
    if entity and entity.blob_value:
      return util.Deserialize(entity.blob_value), entity.mtime
    else:
      return {}, None

  @classmethod
  def SetStatsSummary(cls, d):
    """Sets a the stats summary dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    entity = cls.get_by_key_name(cls._SUMMARY_KEY)
    if not entity:
      entity = cls(key_name=cls._SUMMARY_KEY)
    entity.blob_value = util.Serialize(d)
    entity.put()

  @classmethod
  def GetInstallCounts(cls):
    """Returns tuple (install counts dict, datetime) from Datastore."""
    entity = cls.get_by_key_name(cls._INSTALL_COUNTS_KEY)
    if entity and entity.blob_value:
      return util.Deserialize(entity.blob_value), entity.mtime
    else:
      return {}, None

  @classmethod
  def SetInstallCounts(cls, d):
    """Sets a the install counts dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    entity = cls.get_by_key_name(cls._INSTALL_COUNTS_KEY)
    if not entity:
      entity = cls(key_name=cls._INSTALL_COUNTS_KEY)
    entity.blob_value = util.Serialize(d)
    entity.put()

  @classmethod
  def GetPendingCounts(cls):
    """Returns tuple (pending counts dict, datetime) from Datastore."""
    entity = cls.get_by_key_name(cls._PENDING_COUNTS_KEY)
    if entity and entity.blob_value:
      return util.Deserialize(entity.blob_value), entity.mtime
    else:
      return {}, None

  @classmethod
  def SetPendingCounts(cls, d):
    """Sets a the pending counts dictionary to Datastore.

    Args:
      d: dict of summary data.
    """
    entity = cls.get_by_key_name(cls._PENDING_COUNTS_KEY)
    if not entity:
      entity = cls(key_name=cls._PENDING_COUNTS_KEY)
    entity.blob_value = util.Serialize(d)
    entity.put()

  @classmethod
  def SetMsuUserSummary(cls, d, since=None, tmp=False):
    """Sets the msu user summary dictionary to Datstore.

    Args:
      d: dict of summary data.
    """
    if since is not None:
      since = '_since_%s_' % since
    else:
      since = ''
    key = '%s%s%s' % (cls._MSU_USER_SUMMARY_KEY, since, tmp * '_tmp')
    entity = cls.get_by_key_name(key)
    if not entity:
      entity = cls(key_name=key)
    entity.blob_value = util.Serialize(d)
    entity.put()

  @classmethod
  def GetMsuUserSummary(cls, since, tmp=False):
    """Gets the MSU user summary dictionary from Datastore.

    Returns:
      (dict of summary data, datetime mtime)
    """
    if since is not None:
      since = '_since_%s_' % since
    else:
      since = ''
    key = '%s%s%s' % (cls._MSU_USER_SUMMARY_KEY, since, tmp * '_tmp')
    entity = cls.get_by_key_name(key)
    if entity and entity.blob_value:
      return util.Deserialize(entity.blob_value), entity.mtime
    else:
      return None

  @classmethod
  def DeleteMsuUserSummary(cls, since, tmp=False):
    """Deletes the MSU user summary entity from Datastore."""
    if since is not None:
      since = '_since_%s_' % since
    else:
      since = ''
    key = '%s%s%s' % (cls._MSU_USER_SUMMARY_KEY, since, tmp * '_tmp')
    entity = cls.get_by_key_name(key)
    if not entity:
      return None
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


class BaseMunkiModel(BasePlistModel):
  """Base class for Munki related models."""

  name = db.StringProperty()
  mtime = db.DateTimeProperty(auto_now=True)


class BaseCompressedMunkiModel(BaseModel):
  """Base class for Munki related models."""

  name = db.StringProperty()
  mtime = db.DateTimeProperty(auto_now=True)
  plist = CompressedUtf8BlobProperty()  # catalog/manifest/pkginfo plist file.


class AppleSUSCatalog(BaseCompressedMunkiModel):
  """Apple Software Update Service Catalog."""

  last_modified_header = db.StringProperty()


class AppleSUSProduct(BaseModel):
  """Apple Software Update Service products."""

  product_id = db.StringProperty()
  name = db.StringProperty()
  version = db.StringProperty()
  description = db.TextProperty()
  apple_mtime = db.DateTimeProperty()
  tracks = db.StringListProperty()
  mtime = db.DateTimeProperty(auto_now=True)
  # If manual_override, then auto-promotion will not occur.
  manual_override = db.BooleanProperty(default=False)
  # If deprecated, then the product is entirely hidden and unused.
  deprecated = db.BooleanProperty(default=False)


class Catalog(BaseMunkiModel):
  """Munki catalog.

  These will be automatically generated on App Engine whenever an admin uploads
  a pkginfo file.

  Note: There is also an "all" catalog that includes all packages.
  """


class Manifest(BaseMunkiModel):
  """Munki manifest file.

  These are manually generated and managed on App Engine by admins.
  Name property is something like: stable-leopard, unstable-snowleopard, etc.
  """

  enabled = db.BooleanProperty(default=True)
  # admin username that created the manifest.
  user = db.UserProperty(auto_current_user=True)


class PackageInfo(BaseMunkiModel):
  """Munki pkginfo file, Blobstore key, etc., for the corresponding package.

  _plist contents are generated offline by Munki tools and uploaded by admins.

  name is something like: Adobe Flash, Mozilla Firefox, MS Office, etc.
  """

  # catalog names this pkginfo belongs to; unstable, testing, stable.
  catalogs = db.StringListProperty()
  # manifest names this pkginfo belongs to; unstable, testing, stable.
  manifests = db.StringListProperty()
  # install types for this pkg; managed_installs, managed_uninstalls,
  #   managed_updates, etc.
  install_types = db.StringListProperty()
  # admin username that uploaded pkginfo.
  user = db.StringProperty()
  # filename for the package data
  filename = db.StringProperty()
  # key to Blobstore for package data.
  blobstore_key = db.StringProperty()
  # sha256 hash of package data
  pkgdata_sha256 = db.StringProperty()
  # munki name in the form of pkginfo '%s-%s' % (display_name, version)
  # this property is automatically updated on put()
  munki_name = db.StringProperty()
  # datetime when the PackageInfo was initially created.
  created = db.DateTimeProperty(auto_now_add=True)

  def IsSafeToModify(self):
    """Returns True if the pkginfo is modifiable, False otherwise."""
    if common.STABLE in self.manifests:
      return False
    elif common.TESTING in self.manifests:
      return False
    return True

  def _GetMunkiName(self):
    """Returns the str Munki name of the PackageInfo entity."""
    if not self._plist:
      return None
    pl = plist_lib.MunkiPackageInfoPlist(self._plist.encode('utf-8'))
    pl.Parse()
    return pl.GetMunkiName()

  def put(self, *args, **kwargs):
    """Perform datastore put operation.

    Args:
      args: list, optional, args to superclass put()
      kwargs: dict, optional, keyword args to superclass put()
    Returns:
      return value from superclass put()
    """
    self.munki_name = self._GetMunkiName()
    return super(PackageInfo, self).put(*args, **kwargs)


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

  @classmethod
  def GenerateInstance(cls, mod_type, mod_value, munki_pkg_name, **kwargs):
    """Returns a model instance for the passed mod_type.

    Args:
      mod_type: str, modification type like 'site', 'owner', etc.
      mod_value: str, modification key value, like 'foouser', or 'foouuid'.
      munki_pkg_name: str, name of the munki package to inject, like Firefox.
      kwargs: any other properties to set on the model instance.
    Returns:
      A model instance with key_name, value and the model-specific mod key value
      properties already set.
    """
    key_name = '%s##%s' % (mod_value, munki_pkg_name)
    model = MANIFEST_MOD_MODELS.get(mod_type, None)
    if not model:
      raise ValueError
    m = model(key_name=key_name)
    setattr(m, mod_type, mod_value)
    m.value = munki_pkg_name
    for kw in kwargs:
      setattr(m, kw, kwargs[kw])
    return m


class SiteManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by site."""

  site = db.StringProperty()  # NYC, MTV, etc.


class OSVersionManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by OS version."""

  os_version = db.StringProperty()  # 10.6.5


class OwnerManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by owner."""

  owner = db.StringProperty()  # foouser

OwnerManifestModification.MemcacheAddAutoUpdateTask(
    'MemcacheWrappedPropMapGenerate', 'owner', defer_if_locked=True)


class UuidManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by computer."""

  uuid = db.StringProperty()  # Computer.uuid format

UuidManifestModification.MemcacheAddAutoUpdateTask(
    'MemcacheWrappedPropMapGenerate', 'uuid', defer_if_locked=True)


MANIFEST_MOD_MODELS = {
    'owner': OwnerManifestModification,
    'uuid': UuidManifestModification,
    'site': SiteManifestModification,
    'os_version': OSVersionManifestModification,
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
  office = db.StringProperty()
  site = db.StringProperty()