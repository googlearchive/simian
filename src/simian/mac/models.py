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
from google.appengine.ext import db
from google.appengine.api import memcache
from simian.mac import zip
from simian.mac.common import util

class Error(Exception):
  """Class for domain exceptions."""


class InvalidArgumentsError(Error):
  """Invalid arguments were passed."""


# Simian #####################################################################

COMPUTER_ACTIVE_DAYS = 30


class BaseModel(db.Model):
  """Abstract base model with useful generic methods."""

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
      memcache.set(memcache_key, entity, memcache_secs)

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
  uuid = db.StringProperty()  # OSX or Puppet UUID; undecided.
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
    query = cls.all().filter('preflight_datetime <', earliest_active_date)
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
      query = cls.all().filter('preflight_datetime <', earliest_active_date)
      query.with_cursor(cursor)
    return count

  def put(self):
    """Forcefully set active according to preflight_datetime."""
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
  status = db.StringProperty()  # SUCCESSFUL, FAILURE, etc.
  on_corp = db.BooleanProperty()  # True for install on corp, False otherwise.


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


class KeyValueCache(BaseModel):
  """Model for a generic key value pair storage."""

  text_value = db.TextProperty()
  mtime = db.DateTimeProperty(auto_now=True)


class ReportsCache(KeyValueCache):
  """Model for various reports data caching."""

  _SUMMARY_KEY = 'summary'
  _INSTALL_COUNTS_KEY = 'install_counts'
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
    return util.Deserialize(entity.blob_value), entity.mtime

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
    if not entity:
      return {}, None
    return util.Deserialize(entity.blob_value), entity.mtime

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
    if not entity:
      return None
    return util.Deserialize(entity.blob_value), entity.mtime

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
  _plist = db.BlobProperty()  # catalog/manifest/pkginfo plist file.

  def _GetPlist(self):
    """Returns the _plist property encoded in utf-8."""
    return unicode(zip.CompressedText(self._plist)).encode('utf-8')

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
      self._plist = db.Blob(
          zip.CompressedText(plist).Compressed())
    else:
      self._plist = db.Blob(
          zip.CompressedText(plist, encoding='utf-8').Compressed())

  plist = property(_GetPlist, _SetPlist)


class AppleSUSCatalog(BaseCompressedMunkiModel):
  """Apple Software Update Service Catalog."""

  last_modified_header = db.StringProperty()


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

  Note: When we start doing single client targeting with Stuff integration,
    these may be automatically generated with names containing destination
    hostnames.
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


class BaseManifestModification(BaseModel):
  """Manifest modifications for dynamic manifest generation."""

  enabled = db.BooleanProperty(default=True)
  install_type = db.StringProperty()  # managed_installs, managed_updates, etc.
  # value to be added or removed from the install_type above.
  value = db.StringProperty()  # fooinstallname. -fooinstallname to remove it.
  manifests = db.StringListProperty()  # ['unstable', 'testing']


class SiteManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by site."""

  site = db.StringProperty()  # NYC, MTV, etc.


class OSVersionManifestModification(BaseManifestModification):
  """Manifest modifications for dynamic manifest generation by OS version."""

  os_version = db.StringProperty()  # 10.6.5


# Other models.


class FirstClientConnection(BaseModel):
  """Model to keep track of new clients and whether they've been emailed."""

  mtime = db.DateTimeProperty(auto_now_add=True)
  computer = db.ReferenceProperty(Computer)
  owner = db.StringProperty()
  hostname = db.StringProperty()
  emailed = db.DateTimeProperty()
  office = db.StringProperty()
  site = db.StringProperty()