#!/usr/bin/env python
# 
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""App Engine Models related to Munki."""




import datetime
import logging
import re

from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import db
from google.appengine.ext import deferred

from simian.mac import common
from simian.mac.common import gae_util
from simian.mac.models import base
from simian.mac.munki import plist as plist_lib


# Munki catalog plist XML with Apple DTD/etc, and empty array for filling.
CATALOG_PLIST_XML = '%s<array>\n%s\n</array>%s' % (
    plist_lib.PLIST_HEAD, '%s', plist_lib.PLIST_FOOT)


class MunkiError(base.Error):
  """Class for domain specific exceptions."""


class CatalogGenerateError(MunkiError):
  """There was an error generating a catalog."""


class ManifestGenerateError(MunkiError):
  """There was an error updating the manifest."""


class PackageInfoUpdateError(MunkiError):
  """Error during PackageInfo Update."""


class PackageInfoLockError(PackageInfoUpdateError):
  """Could not obtain lock on PackageInfo."""


class PackageInfoAccessError(PackageInfoUpdateError):
  """Access denied for this user."""


class PackageInfoNotFoundError(PackageInfoUpdateError):
  """Requested PackageInfo not found."""


class PackageInfoNotSafeError(PackageInfoUpdateError):
  """It's not safe to edit this PackageInfo."""


class BaseMunkiModel(base.BasePlistModel):
  """Base class for Munki related models."""

  name = db.StringProperty()
  mtime = db.DateTimeProperty(auto_now=True)


class Catalog(BaseMunkiModel):
  """Munki catalog.

  These will be automatically generated on App Engine whenever an admin uploads
  a pkginfo file.

  Note: There is also an "all" catalog that includes all packages.
  """

  PLIST_LIB_CLASS = plist_lib.MunkiPlist

  @classmethod
  def Generate(cls, name, delay=0):
    """Generates a Catalog plist and entity from matching PackageInfo entities.

    Args:
      name: str, catalog name. all PackageInfo entities with this name in the
          "catalogs" property will be included in the generated catalog.
      delay: int, if > 0, Generate call is deferred this many seconds.
    """
    if delay:
      now = datetime.datetime.utcnow()
      now_str = '%s-%d' % (now.strftime('%Y-%m-%d-%H-%M-%S'), now.microsecond)
      deferred_name = 'create-catalog-%s-%s' % (name, now_str)
      deferred.defer(cls.Generate, name, _name=deferred_name, _countdown=delay)
      return

    lock = 'catalog_lock_%s' % name
    # Obtain a lock on the catalog name.
    if not gae_util.ObtainLock(lock):
      # If catalog creation for this name is already in progress then delay.
      logging.debug('Catalog creation for %s is locked. Delaying....', name)
      cls.Generate(name, delay=10)
      return

    #logging.debug('Creating catalog: %s', name)
    try:
      pkgsinfo_dicts = []
      package_infos = PackageInfo.all().filter('catalogs =', name)
      if not package_infos:
        # TODO(user): if this happens we probably want to notify admins...
        raise CatalogGenerateError('No pkgsinfo found with catalog: %s' % name)

      for p in package_infos:
        pkgsinfo_dicts.append(p.plist.GetXmlContent(indent_num=1))

      catalog = CATALOG_PLIST_XML % '\n'.join(pkgsinfo_dicts)

      c = cls.get_or_insert(name)
      c.name = name
      c.plist = catalog
      c.put()
      cls.ResetMemcacheWrap(name)
      #logging.debug('Generated catalog successfully: %s', name)
      # Generate manifest for newly generated catalog.
      Manifest.Generate(name, delay=1)
    except (CatalogGenerateError, db.Error, plist_lib.Error):
      logging.exception('Catalog.Generate failure for catalog: %s', name)
      gae_util.ReleaseLock(lock)
      raise
    gae_util.ReleaseLock(lock)


class Manifest(BaseMunkiModel):
  """Munki manifest file.

  These are manually generated and managed on App Engine by admins.
  Name property is something like: stable-leopard, unstable-snowleopard, etc.
  """

  PLIST_LIB_CLASS = plist_lib.MunkiManifestPlist

  enabled = db.BooleanProperty(default=True)

  @classmethod
  def Generate(cls, name, delay=0):
    """Generates a Manifest plist and entity from matching PackageInfo entities.

    Args:
      name: str, manifest name. all PackageInfo entities with this name in the
          "manifests" property will be included in the generated manifest.
      delay: int. if > 0, Generate call is deferred this many seconds.
    """
    if delay:
      now = datetime.datetime.utcnow()
      now_str = '%s-%d' % (now.strftime('%Y-%m-%d-%H-%M-%S'), now.microsecond)
      deferred_name = 'create-manifest-%s-%s' % (name, now_str)
      deferred.defer(cls.Generate, name, _name=deferred_name, _countdown=delay)
      return

    lock = 'manifest_lock_%s' % name
    if not gae_util.ObtainLock(lock):
      logging.debug(
          'Manifest.Generate for %s is locked. Delaying....', name)
      cls.Generate(name, delay=5)
      return

    #logging.debug('Creating manifest: %s', name)
    try:
      package_infos = PackageInfo.all().filter('manifests =', name)
      if not package_infos:
        # TODO(user): if this happens we probably want to notify admins...
        raise ManifestGenerateError('PackageInfo entities found: %s' % name)

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

      # Save the new manifest to Datastore.
      manifest_entity = cls.get_or_insert(name)
      # Turn the manifest dictionary into XML.
      manifest_entity.plist.SetContents(manifest_dict)
      manifest_entity.put()
      cls.ResetMemcacheWrap(name)
      #logging.debug(
      #    'Manifest %s created successfully', name)
    except (ManifestGenerateError, db.Error, plist_lib.Error):
      logging.exception('Manifest.Generate failure: %s', name)
      gae_util.ReleaseLock(lock)
      raise
    gae_util.ReleaseLock(lock)


class PackageInfo(BaseMunkiModel):
  """Munki pkginfo file, Blobstore key, etc., for the corresponding package.

  _plist contents are generated offline by Munki tools and uploaded by admins.

  name is something like: Adobe Flash, Mozilla Firefox, MS Office, etc.
  """

  PLIST_LIB_CLASS = plist_lib.MunkiPackageInfoPlist
  AVG_DURATION_TEXT = (
      '%d users have installed this with an average duration of %d seconds.')
  AVG_DURATION_REGEX = re.compile(
      '\d+ users have installed this with an average duration of \d+ seconds\.')

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
  # str group name(s) in common.MANIFEST_MOD_GROUPS that have access to inject
  # this package into manifests.
  manifest_mod_access = db.StringListProperty()

  def _GetDescription(self):
    """Returns only admin portion of the desc, omitting avg duration text."""
    desc = self.plist.get('description', None)
    if desc:
      match = self.AVG_DURATION_REGEX.search(desc)
      if match:
        avg_duration_text = match.group(0)
        return desc.replace(avg_duration_text, '').strip()
    return desc

  def _SetDescription(self, desc):
    """Sets the description to the plist, preserving any avg duration text."""
    if self.AVG_DURATION_REGEX.search(desc):
      # If the new description has the avg duration text, just keep it all.
      self.plist['description'] = desc
    else:
      # Otherwise append the old avg duration text to the new description.
      match = self.AVG_DURATION_REGEX.search(self.plist.get('description', ''))
      if match:
        self.plist['description'] = '%s\n\n%s' % (desc, match.group(0))
      else:
        self.plist['description'] = desc

    # Update the plist property with the new description.
    self.plist = self.plist.GetXml()

  description = property(_GetDescription, _SetDescription)

  def _GetBlobInfo(self):
    """Returns the blobstore.BlobInfo object for the PackageInfo."""
    if not self.blobstore_key:
      return None
    return blobstore.BlobInfo.get(self.blobstore_key)

  def _SetBlobInfo(self, blob_info):
    """Sets the blobstore_key property from a given blobstore.BlobInfo object.

    This mimics the new blobstore.BlobReferenceProperty() without requiring
    a schema change, which isn't fun for external Simian customers.
    """
    self.blobstore_key = str(blob_info.key())

  blob_info = property(_GetBlobInfo, _SetBlobInfo)

  def IsSafeToModify(self):
    """Returns True if the pkginfo is modifiable, False otherwise."""
    if common.STABLE in self.manifests:
      return False
    elif common.TESTING in self.manifests:
      return False
    return True

  def MakeSafeToModify(self):
    """Modifies a PackageInfo such that it is safe to modify."""
    self.Update(catalogs=[], manifests=[])

  def put(self, *args, **kwargs):
    """Put to Datastore, generating and setting the "munki_name" property.

    Args:
      args: list, optional, args to superclass put()
      kwargs: dict, optional, keyword args to superclass put()
    Returns:
      return value from superclass put()
    Raises:
      PackageInfoUpdateError: pkginfo property validation failed.
    """
    # Ensure any defined manifests have matching catalogs.
    for manifest in self.manifests:
      if manifest not in self.catalogs:
        raise PackageInfoUpdateError(
            'manifest did not have matching catalog: %s' % manifest)

    # Always update the munki_name property with the latest Pkg-<Version> name
    # for backwards compatibility.
    try:
      self.munki_name = self.plist.GetMunkiName()
    except plist_lib.PlistNotParsedError:
      self.munki_name = None
    return super(PackageInfo, self).put(*args, **kwargs)

  def delete(self, *args, **kwargs):
    """Deletes a PackageInfo and cleans up associated data in other models.

    Any Blobstore blob associated with the PackageInfo is deleted, and all
    Catalogs the PackageInfo was a member of are regenerated.

    Returns:
      return value from superlass delete()
    """
    ret = super(PackageInfo, self).delete(*args, **kwargs)
    for catalog in self.catalogs:
      Catalog.Generate(catalog, delay=5)
    if self.blobstore_key:
      gae_util.SafeBlobDel(self.blobstore_key)
    return ret

  @classmethod
  def _PutAndLogPackageInfoUpdate(
      cls, pkginfo, original_plist, changed_catalogs):
    """Helper method called by Update or UpdateFromPlist to put/log the update.

    Args:
      pkginfo: a PackageInfo entity ready to be put to Datastore.
      original_plist: str XML of the original pkginfo plist, before updates.
      changed_catalogs: a list of str catalog names that have changed and need
          to be regenerated.
    Raises:
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    pkginfo.put()

    delay = 0
    for track in sorted(changed_catalogs, reverse=True):
      delay += 5
      Catalog.Generate(track, delay=delay)

    # Log admin pkginfo put to Datastore.
    user = users.get_current_user().email()
    log = base.AdminPackageLog(
        user=user, action='pkginfo', filename=pkginfo.filename,
        catalogs=pkginfo.catalogs, manifests=pkginfo.manifests,
        original_plist=original_plist, install_types=pkginfo.install_types,
        manifest_mod_access=pkginfo.manifest_mod_access)
    # The plist property is a py property of _plist, and therefore cannot be
    # set in the constructure, so set here.
    log.plist = pkginfo.plist
    log.put()

  @classmethod
  def _New(cls, key_name):
    """Returns a new PackageInfo entity with a given key name.

    Only needed for unit test stubbing purposes.

    Args:
      key_name: str, key name for the entity.
    Returns:
      PackageInfo object isntance.
    """
    return cls(key_name=key_name)

  @classmethod
  def UpdateFromPlist(cls, plist, create_new=False):
    """Updates a PackageInfo entity from a plist_lib.ApplePlist object or str.

    Args:
      plist: str or plist_lib.ApplePlist object.
      create_new: bool, optional, default False. If True, create a new
          PackageInfo entity, only otherwise update an existing one.

    Raises:
      PackageInfoLockError: if the package is already locked in the datastore.
      PackageInfoNotFoundError: if the filename is not a key in the datastore.
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    if type(plist) is str or type(plist) is unicode:
      plist = plist_lib.MunkiPackageInfoPlist(plist)
      plist.EncodeXml()
      try:
        plist.Parse()
      except plist_lib.PlistError, e:
        raise PackageInfoUpdateError(
            'plist_lib.PlistError parsing plist XML: %s', str(e))

    filename = plist['installer_item_location']

    lock = 'pkgsinfo_%s' % filename
    if not gae_util.ObtainLock(lock, timeout=5.0):
      raise PackageInfoLockError('This PackageInfo is locked.')


    if create_new:
      if cls.get_by_key_name(filename):
        gae_util.ReleaseLock(lock)
        raise PackageInfoUpdateError(
            'An existing pkginfo exists for: %s' % filename)
      pkginfo = cls._New(filename)
      pkginfo.filename = filename
      # If we're uploading a new pkginfo plist, wipe out catalogs.
      plist['catalogs'] = []
      original_plist = None
    else:
      pkginfo = cls.get_by_key_name(filename)
      if not pkginfo:
        gae_util.ReleaseLock(lock)
        raise PackageInfoNotFoundError('pkginfo not found: %s' % filename)
      original_plist = pkginfo.plist.GetXml()

    if not pkginfo.IsSafeToModify():
      gae_util.ReleaseLock(lock)
      raise PackageInfoUpdateError(
          'PackageInfo is not safe to modify; move to unstable first.')

    pkginfo.plist = plist
    pkginfo.name = plist['name']
    changed_catalogs = set(pkginfo.catalogs + plist['catalogs'])
    pkginfo.catalogs = plist['catalogs']
    pkginfo.pkgdata_sha256 = plist['installer_item_hash']
    try:
      cls._PutAndLogPackageInfoUpdate(pkginfo, original_plist, changed_catalogs)
    except PackageInfoUpdateError:
      gae_util.ReleaseLock(lock)
      raise

    gae_util.ReleaseLock(lock)

    return pkginfo

  def Update(self, **kwargs):
    """Updates properties and/or plist of an existing PackageInfo entity.

    Omitted properties are left unmodified on the PackageInfo entity.

    Args:
      catalogs: list, optional, a subset of common.TRACKS.
      manifests: list, optional, a subset of common.TRACKS.
      install_types: list, optional, a subset of common.INSTALL_TYPES.
      manifest_mod_access: list, optional, subset of common.MANIFEST_MOD_GROUPS.
      name: str, optional, pkginfo name value.
      display_name: str, optional, pkginfo display_name value.
      unattended_install: boolean, optional, True to set unattended_install.
      description: str, optional, pkginfo description.
      version: str, optional, pkginfo version.
      minimum_os_version: str, optional, pkginfo minimum_os_version value.
      maximum_os_version: str, optional, pkginfo maximum_os_version value.
      force_install_after_date: datetime, optional, pkginfo
          force_install_after_date value.

    Raises:
      PackageInfoLockError: if the package is already locked in the datastore.
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    catalogs = kwargs.get('catalogs')
    manifests = kwargs.get('manifests')
    install_types = kwargs.get('install_types')
    manifest_mod_access = kwargs.get('manifest_mod_access')
    name = kwargs.get('name')
    display_name = kwargs.get('display_name')
    unattended_install = kwargs.get('unattended_install')
    description = kwargs.get('description')
    version = kwargs.get('version')
    minimum_os_version = kwargs.get('minimum_os_version')
    maximum_os_version = kwargs.get('maximum_os_version')
    force_install_after_date = kwargs.get('force_install_after_date')

    original_plist = self.plist.GetXml()

    lock = 'pkgsinfo_%s' % self.filename
    if not gae_util.ObtainLock(lock, timeout=5.0):
      raise PackageInfoLockError

    if self.IsSafeToModify():
      if name is not None:
        self.plist['name'] = name
        self.name = name

      if description is not None:
        self.description = description

      if 'display_name' in self.plist and display_name == '':
        self.plist.RemoveDisplayName()
      elif display_name != '' and display_name is not None:
        self.plist.SetDisplayName(display_name)

      if install_types is not None:
        self.install_types = install_types

      if manifest_mod_access is not None:
        self.manifest_mod_access = manifest_mod_access

      if version is not None:
        self.plist['version'] = version

      if minimum_os_version is not None:
        if not minimum_os_version and 'minimum_os_version' in self.plist:
          del self.plist['minimum_os_version']
        elif minimum_os_version:
          self.plist['minimum_os_version'] = minimum_os_version

      if maximum_os_version is not None:
        if not maximum_os_version and 'maximum_os_version' in self.plist:
          del self.plist['maximum_os_version']
        elif maximum_os_version:
          self.plist['maximum_os_version'] = maximum_os_version

      if force_install_after_date is not None:
        if force_install_after_date:
          self.plist['force_install_after_date'] = force_install_after_date
        else:
          if 'force_install_after_date' in self.plist:
            del self.plist['force_install_after_date']

      self.plist.SetUnattendedInstall(unattended_install)
    else:
      # If not safe to modify, only catalogs/manifests can be changed.
      for k, v in kwargs.iteritems():
        if v and k not in ['catalogs', 'manifests']:
          gae_util.ReleaseLock(lock)
          raise PackageInfoUpdateError(
              'PackageInfo is not safe to modify; move to unstable first.')

    if catalogs is not None:
      changed_catalogs = set(self.catalogs + catalogs)
      self.catalogs = catalogs
      self.plist['catalogs'] = catalogs
    else:
      changed_catalogs = self.catalogs

    if manifests is not None:
      self.manifests = manifests

    try:
      self._PutAndLogPackageInfoUpdate(self, original_plist, changed_catalogs)
    except PackageInfoUpdateError:
      gae_util.ReleaseLock(lock)
      raise

    gae_util.ReleaseLock(lock)

  @classmethod
  def GetManifestModPkgNames(
      cls, group=common.MANIFEST_MOD_ADMIN_GROUP, only_names=False):
    """Returns a list of package names that a particular group can inject."""
    if group == common.MANIFEST_MOD_ADMIN_GROUP:
      query = cls.all()
    elif group not in common.MANIFEST_MOD_GROUPS:
      return []
    else:
      query = cls.all().filter('manifest_mod_access =', group)
    if only_names:
      return  [e.name for e in query]
    else:
      pkgs = [{'name': e.name, 'munki_name': e.munki_name} for e in query]
      return sorted(pkgs, key=lambda d: unicode.lower(d.get('munki_name')))