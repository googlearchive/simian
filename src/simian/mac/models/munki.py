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
"""App Engine Models related to Munki."""

import datetime
import logging
import os
import re
import urllib

from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import db
from google.appengine.ext import deferred

from simian.mac.common import datastore_locks
from simian.mac import common
from simian.mac.common import gae_util
from simian.mac.common import mail as mail_tool
from simian.mac.models import base
from simian.mac.models import constants
from simian.mac.models import settings
from simian.mac.munki import plist as plist_lib


PACKAGE_LOCK_PREFIX = 'pkgsinfo_'


class MunkiError(base.Error):
  """Class for domain specific exceptions."""


class PackageInfoUpdateError(MunkiError):
  """Error during PackageInfo Update."""


class PackageInfoLockError(PackageInfoUpdateError):
  """Could not obtain lock on PackageInfo."""


class PackageInfoAccessError(PackageInfoUpdateError):
  """Access denied for this user."""


class PackageInfoProposalError(MunkiError):
  """Error during PackageInfoProposal Update."""


class PackageInfoProposalApprovalError(PackageInfoProposalError):
  """User not allowed to approve proposal."""


class PackageInfoNotFoundError(PackageInfoUpdateError):
  """Requested PackageInfo not found."""


class PackageInfoNotSafeError(PackageInfoUpdateError):
  """It's not safe to edit this PackageInfo."""


class BaseMunkiModel(base.BasePlistModel):
  """Base class for Munki related models."""

  name = db.StringProperty()
  mtime = db.DateTimeProperty()

  def put(self, avoid_mtime_update=False, **kwargs):
    if not avoid_mtime_update:
      self.mtime = datetime.datetime.utcnow()

    return super(BaseMunkiModel, self).put(**kwargs)


class Catalog(BaseMunkiModel):
  """Munki catalog.

  These will be automatically generated on App Engine whenever an admin uploads
  a pkginfo file.

  Note: There is also an "all" catalog that includes all packages.
  """

  package_names = db.StringListProperty()

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

    lock_name = 'catalog_lock_%s' % name
    lock = datastore_locks.DatastoreLock(lock_name)
    try:
      lock.Acquire(timeout=600, max_acquire_attempts=2)
    except datastore_locks.AcquireLockError:
      # If catalog creation for this name is already in progress then delay.
      logging.debug('Catalog creation for %s is locked. Delaying....', name)
      cls.Generate(name, delay=10)
      return

    package_names = []
    try:
      midnight = datetime.datetime.combine(
          datetime.date.today(), datetime.time(0, 0))

      # new catalog has updated average install durations,
      # download daily.
      mtimes = [midnight]
      pkgsinfo_dicts = []
      package_infos = PackageInfo.all().filter('catalogs =', name).fetch(None)
      if not package_infos:
        logging.warning('No PackageInfo entities with catalog: %s', name)
      for p in package_infos:
        package_names.append(p.name)
        pkgsinfo_dicts.append(p.plist.GetXmlContent(indent_num=1))
        mtimes.append(p.mtime)

      catalog = constants.CATALOG_PLIST_XML % '\n'.join(pkgsinfo_dicts)

      c = cls.get_or_insert(name)
      c.package_names = package_names
      c.name = name
      c.plist = catalog

      c.mtime = max(mtimes)
      c.put(avoid_mtime_update=True)

      cls.DeleteMemcacheWrap(name)
      # Generate manifest for newly generated catalog.
      Manifest.Generate(name, delay=1)
    except (db.Error, plist_lib.Error):
      logging.exception('Catalog.Generate failure for catalog: %s', name)
      raise
    finally:
      lock.Release()


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

    lock_name = 'manifest_lock_%s' % name
    lock = datastore_locks.DatastoreLock(lock_name)
    try:
      lock.Acquire(timeout=30, max_acquire_attempts=1)
    except datastore_locks.AcquireLockError:
      logging.debug(
          'Manifest.Generate for %s is locked. Delaying....', name)
      cls.Generate(name, delay=5)
      return

    try:
      install_types = {}
      package_infos = PackageInfo.all().filter('manifests =', name).fetch(None)
      if not package_infos:
        logging.warning('No PackageInfo entities with manifest: %s', name)
      for p in package_infos:
        # Add all installs to their appropriate install type containers.
        for install_type in p.install_types:
          if install_type not in install_types:
            install_types[install_type] = []
          install_types[install_type].append(p.name)

      # Generate a dictionary of the manifest data.
      manifest_dict = {'catalogs': [name, 'apple_update_metadata']}
      for k, v in install_types.iteritems():
        manifest_dict[k] = v

      # Save the new manifest to Datastore.
      manifest_entity = cls.get_or_insert(name)
      # Turn the manifest dictionary into XML.
      manifest_entity.plist.SetContents(manifest_dict)
      manifest_entity.put()
      cls.DeleteMemcacheWrap(name)
    except (db.Error, plist_lib.Error):
      logging.exception('Manifest.Generate failure: %s', name)
      raise
    finally:
      lock.Release()


class PackageInfo(BaseMunkiModel):
  """Munki pkginfo file, Blobstore key, etc., for the corresponding package.

  _plist contents are generated offline by Munki tools and uploaded by admins.

  name is something like: Adobe Flash, Mozilla Firefox, MS Office, etc.
  """

  PLIST_LIB_CLASS = plist_lib.MunkiPackageInfoPlist
  AVG_DURATION_TEXT = (
      '%d users have installed this with an average duration of %d seconds.')
  AVG_DURATION_REGEX = re.compile(
      r'\d+ users have installed this with an average duration of '
      r'\d+ seconds\.')

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

    Args:
      blob_info: blobstore.BlobInfo instance.
    """
    self.blobstore_key = str(blob_info.key())

  blob_info = property(_GetBlobInfo, _SetBlobInfo)

  @property
  def approval_required(self):
    if not hasattr(self, '_is_approval_required'):
      self._is_approval_required, _ = settings.Settings.GetItem(
          'approval_required')
    return self._is_approval_required

  @property
  def proposal(self):
    if not hasattr(self, '_proposal'):
      self._proposal = PackageInfoProposal.FindOrCreatePackageInfoProposal(self)
    return self._proposal

  @property
  def catalog_matrix(self):
    return common.util.MakeTrackMatrix(self.catalogs, self.proposal.catalogs)

  @property
  def manifest_matrix(self):
    return common.util.MakeTrackMatrix(self.manifests, self.proposal.manifests)

  def IsSafeToModify(self):
    """Returns True if the pkginfo is modifiable, False otherwise."""
    if self.approval_required:
      return self.proposal.IsPackageInfoSafeToModify()
    else:
      if common.STABLE in self.manifests:
        return False
      elif common.TESTING in self.manifests:
        return False
      return True

  def MakeSafeToModify(self):
    """Modifies a PackageInfo such that it is safe to modify."""
    if self.approval_required:
      self.proposal.MakePackageInfoSafeToModify()
    else:
      self.Update(catalogs=[], manifests=[])

  def put(self, *args, **kwargs):
    """Put to Datastore, generating and setting the "munki_name" property.

    Args:
      *args: list, optional, args to superclass put()
      **kwargs: dict, optional, keyword args to superclass put()
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

    Args:
      *args: list, optional, args to superclass delete()
      **kwargs: dict, optional, keyword args to superclass delete()
    Returns:
      return value from superlass delete()
    """
    ret = super(PackageInfo, self).delete(*args, **kwargs)
    for catalog in self.catalogs:
      Catalog.Generate(catalog, delay=1)
    if self.blobstore_key:
      gae_util.SafeBlobDel(self.blobstore_key)
    return ret

  def VerifyPackageIsEligibleForNewCatalogs(self, new_catalogs):
    """Ensure a package with the same name does not exist in the new catalogs.

    Args:
      new_catalogs: list of str catalogs to verify the package name is not in.
    Raises:
      PackageInfoUpdateError: a new catalog contains a pkg with the same name.
    """
    for catalog in new_catalogs:
      catalog_obj = Catalog.get_by_key_name(catalog)
      if catalog_obj and self.name in catalog_obj.package_names:
        raise PackageInfoUpdateError(
            '%r already exists in %r catalog' % (self.name, catalog))

  @classmethod
  def _PutAndLogPackageInfoUpdate(
      cls, pkginfo, original_plist, original_catalogs):
    """Helper method called by Update or UpdateFromPlist to put/log the update.

    Args:
      pkginfo: a PackageInfo entity ready to be put to Datastore.
      original_plist: str XML of the original pkginfo plist, before updates.
      original_catalogs: list of catalog names the pkg was previously in.
    Returns:
      return AdminPackageLog record.
    Raises:
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    new_catalogs = [c for c in pkginfo.catalogs if c not in original_catalogs]
    pkginfo.VerifyPackageIsEligibleForNewCatalogs(new_catalogs)
    pkginfo.put()

    changed_catalogs = set(original_catalogs + pkginfo.catalogs)
    for track in sorted(changed_catalogs, reverse=True):
      Catalog.Generate(track, delay=1)

    # Log admin pkginfo put to Datastore.
    user = users.get_current_user().email()
    log = base.AdminPackageLog(
        user=user, action='pkginfo', filename=pkginfo.filename,
        catalogs=pkginfo.catalogs,
        manifests=pkginfo.manifests,
        original_plist=original_plist, install_types=pkginfo.install_types,
        manifest_mod_access=pkginfo.manifest_mod_access)
    # The plist property is a py property of _plist, and therefore cannot be
    # set in the constructure, so set here.
    log.plist = pkginfo.plist
    log.put()

    return log

  def PutAndLogFromProposal(self, original_plist, original_catalogs):
    if self.proposal.status == 'approved':
      self._PutAndLogPackageInfoUpdate(self, original_plist, original_catalogs)

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
    Returns:
      pkginfo: Returns updated PackageInfo object.
      log: Returns AdminPackageLog record.
    Raises:
      PackageInfoLockError: if the package is already locked in the datastore.
      PackageInfoNotFoundError: if the filename is not a key in the datastore.
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    if isinstance(plist, basestring) or isinstance(plist, unicode):
      plist = plist_lib.MunkiPackageInfoPlist(plist)
      plist.EncodeXml()
      try:
        plist.Parse()
      except plist_lib.PlistError as e:
        raise PackageInfoUpdateError(
            'plist_lib.PlistError parsing plist XML: %s' % str(e))

    filename = plist['installer_item_location']

    lock = GetLockForPackage(filename)
    try:
      lock.Acquire(timeout=600, max_acquire_attempts=5)
    except datastore_locks.AcquireLockError:
      raise PackageInfoLockError('This PackageInfo is locked.')

    if create_new:
      if cls.get_by_key_name(filename):
        lock.Release()
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
        lock.Release()
        raise PackageInfoNotFoundError('pkginfo not found: %s' % filename)
      original_plist = pkginfo.plist.GetXml()

    if not pkginfo.IsSafeToModify():
      lock.Release()
      raise PackageInfoUpdateError(
          'PackageInfo is not safe to modify; move to unstable first.')

    pkginfo.plist = plist
    pkginfo.name = plist['name']
    original_catalogs = pkginfo.catalogs
    pkginfo.catalogs = plist['catalogs']
    pkginfo.pkgdata_sha256 = plist['installer_item_hash']
    try:
      log = cls._PutAndLogPackageInfoUpdate(
          pkginfo, original_plist, original_catalogs)
    except PackageInfoUpdateError:
      lock.Release()
      raise

    lock.Release()

    return pkginfo, log

  def Update(self, **kwargs):
    """Updates properties and/or plist of an existing PackageInfo entity.

    Omitted properties are left unmodified on the PackageInfo entity.

    Args:
      **kwargs: many, below:
          catalogs: list, optional, a subset of common.TRACKS.
          manifests: list, optional, a subset of common.TRACKS.
          install_types: list, optional, a subset of common.INSTALL_TYPES.
          manifest_mod_access: list, optional, subset of
            common.MANIFEST_MOD_GROUPS.
          name: str, optional, pkginfo name value.
          display_name: str, optional, pkginfo display_name value.
          unattended_install: boolean, optional, True to set unattended_install.
          unattended_uninstall: boolean, optional, True to set
            unattended_uninstall.
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
    unattended_uninstall = kwargs.get('unattended_uninstall')
    description = kwargs.get('description')
    version = kwargs.get('version')
    minimum_os_version = kwargs.get('minimum_os_version')
    maximum_os_version = kwargs.get('maximum_os_version')
    category = kwargs.get('category')
    developer = kwargs.get('developer')
    force_install_after_date = kwargs.get('force_install_after_date')

    original_plist = self.plist.GetXml()

    lock = GetLockForPackage(self.filename)
    try:
      lock.Acquire(timeout=600, max_acquire_attempts=5)
    except datastore_locks.AcquireLockError:
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
      self.plist.SetUnattendedUninstall(unattended_uninstall)
      self.plist['category'] = category
      self.plist['developer'] = developer
    else:
      # If not safe to modify, only catalogs/manifests can be changed.
      for k, v in kwargs.iteritems():
        if v and k not in ['catalogs', 'manifests']:
          if self.approval_required:
            failure_message = ('PackageInfo is not safe to modify;'
                               ' please remove from catalogs first.')
          else:
            failure_message = ('PackageInfo is not safe to modify;'
                               ' please move to unstable first.')
          lock.Release()
          raise PackageInfoUpdateError(failure_message)

    original_catalogs = self.catalogs

    if self.approval_required and (
        catalogs != self.catalogs or manifests != self.manifests):
      self.proposal.Propose(catalogs=catalogs, manifests=manifests)
    else:
      if catalogs is not None:
        self.catalogs = catalogs
        self.plist['catalogs'] = catalogs
      if manifests is not None:
        self.manifests = manifests

    try:
      self._PutAndLogPackageInfoUpdate(self, original_plist, original_catalogs)
    except PackageInfoUpdateError:
      lock.Release()
      raise

    lock.Release()

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


class PackageInfoProposal(PackageInfo):
  """Proposed settings for a package."""

  # user who approved catalogs.
  approver = db.StringProperty()
  # status of proposal. One of 'proposed', 'approved', 'rejected'.
  status = db.StringProperty()

  # properties that will get copied between PackageInfo and PackageInfoProposal
  # objects
  COMMON_PROPERTIES = ['catalogs', 'manifests', 'install_types', 'plist',
                       'munki_name', 'manifest_mod_access', 'filename',
                       'name', 'pkgdata_sha256', 'manifest_mod_access']

  @classmethod
  def _New(cls, pkginfo):
    new_pkginfo_proposal = cls(key_name=pkginfo.filename)
    for key in cls.COMMON_PROPERTIES:
      value = getattr(pkginfo, key)
      setattr(new_pkginfo_proposal, key, value)
    new_pkginfo_proposal.user = users.get_current_user().email()
    new_pkginfo_proposal.pkginfo = pkginfo
    return new_pkginfo_proposal

  @property
  def proposal_in_flight(self):
    if self.status == 'proposed':
      return True
    return False

  def _GetPkginfo(self):
    if not hasattr(self, '_pkginfo'):
      self._pkginfo = PackageInfo.get_by_key_name(self.filename)
    return self._pkginfo

  def _SetPkginfo(self, pkginfo):
    self._pkginfo = pkginfo

  pkginfo = property(_GetPkginfo, _SetPkginfo)

  @property
  def catalog_matrix(self):
    return common.util.MakeTrackMatrix(self.pkginfo.catalogs, self.catalogs)

  @property
  def manifest_matrix(self):
    return common.util.MakeTrackMatrix(self.pkginfo.manifests, self.manifests)

  @classmethod
  def FindOrCreatePackageInfoProposal(cls, pkginfo):
    proposal = PackageInfoProposal.get_by_key_name(pkginfo.filename)
    return proposal or cls._New(pkginfo)

  def IsPackageInfoSafeToModify(self):
    """Returns True if the pkginfo is modifiable, False otherwise."""
    if self.proposal_in_flight:
      return False
    elif hasattr(self.pkginfo, 'catalogs') and self.pkginfo.catalogs:
      return False
    elif hasattr(self.pkginfo, 'manifests') and self.pkginfo.manifests:
      return False
    else:
      return True

  @classmethod
  def _PutAndLogPackageInfoProposalUpdate(
      cls, pkginfo_proposal, original_plist, original_catalogs,
      action='propose'):
    """Helper method called to put/log the update.

    Args:
      pkginfo_proposal: a PackageInfoProposal entity to be put to Datastore.
      original_plist: str XML of the original pkginfo plist, before updates.
      original_catalogs: list of catalog names the pkg was previously in.
      action: str one of 'propose', 'approve', 'reject'.
    Raises:
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    pkginfo_proposal.put()

    changed_catalogs = set(original_catalogs + pkginfo_proposal.catalogs)
    for track in sorted(changed_catalogs, reverse=True):
      Catalog.Generate(track)

    # Log admin pkginfo proposal put to Datastore.
    log = base.AdminPackageProposalLog(
        user=pkginfo_proposal.user, action=action,
        filename=pkginfo_proposal.filename,
        catalogs=pkginfo_proposal.catalogs,
        manifests=pkginfo_proposal.manifests,
        original_plist=original_plist,
        install_types=pkginfo_proposal.install_types,
        manifest_mod_access=pkginfo_proposal.manifest_mod_access,
        approver=pkginfo_proposal.approver)
    # The plist property is a py property of _plist, and therefore cannot be
    # set in the constructure, so set here.
    log.plist = pkginfo_proposal.plist
    log.put()

  def MakePackageInfoSafeToModify(self):
    """Proposes to make a PackageInfo safe to modify."""
    self.Propose(catalogs=[], manifests=[])

  def Propose(self, **kwargs):
    """Proposes changes to a package.

    Args:
      **kwargs: dict, changes being proposed.
    Raises:
      PackageInfoUpdateError: there were validation problems with the pkginfo.
    """
    for key in self.COMMON_PROPERTIES:
      setattr(self, key, getattr(self.pkginfo, key))

    for k, v in kwargs.iteritems():
      setattr(self, k, v)
    self.status = 'proposed'

    self._PutAndLogPackageInfoProposalUpdate(
        self, self.pkginfo.plist.GetXml(), self.catalogs,
        action='propose')
    self.ProposalMailer('proposal')

  def ApproveProposal(self):
    """Approve a pending proposal.

    Raises:
      PackageInfoProposalApprovalError: Approver not alloed to approve.
      PackageInfoLockError: PackageInfo is locked.
      PackageInfoUpdateError: Package is not eligible for catalogs.
    """
    lock = GetLockForPackage(self.filename)
    try:
      lock.Acquire(timeout=600, max_acquire_attempts=5)
    except datastore_locks.AcquireLockError:
      raise PackageInfoLockError

    new_catalogs = [c for c in self.catalogs if c not in self.pkginfo.catalogs]

    try:
      self.pkginfo.VerifyPackageIsEligibleForNewCatalogs(
          new_catalogs)
    except PackageInfoUpdateError:
      lock.Release()
      raise

    approver = users.get_current_user().email()
    if approver == self.user:
      raise PackageInfoProposalApprovalError

    self.approver = approver
    self.status = 'approved'

    self._PutAndLogPackageInfoProposalUpdate(
        self, self.pkginfo.plist.GetXml(), self.catalogs, action='approve')

    original_plist = self.pkginfo.plist.GetXml()
    original_catalogs = self.pkginfo.catalogs

    for key in self.COMMON_PROPERTIES:
      setattr(self.pkginfo, key, getattr(self, key))

    self.pkginfo.PutAndLogFromProposal(original_plist, original_catalogs)

    lock.Release()

    self.ProposalMailer('approval')

    self.delete()

  def RejectProposal(self):
    """Deletes proposal without changing package."""
    self.approver = users.get_current_user().email()
    self.status = 'rejected'
    self._PutAndLogPackageInfoProposalUpdate(
        self, self.pkginfo.plist.GetXml(),
        self.pkginfo.catalogs, action='reject')

    self.ProposalMailer('rejection')

    self.delete()

  def ProposalMailer(self, action):
    """Notifies admins of proposed changes and changed proposals.

    Args:
      action: string, defines what message will be sent.
    """
    current_user = users.get_current_user()
    current_user_nick = current_user.nickname()

    body = self._BuildProposalBody(os.environ.get('DEFAULT_VERSION_HOSTNAME'),
                                   self.filename)

    if action == 'proposal':
      subject = 'Proposal for %s by %s' % (self.filename, current_user_nick)
    elif action == 'approval':
      subject = 'Proposal Approved for %s by %s' % (
          self.filename, current_user_nick)
    elif action == 'rejection':
      subject = 'Proposal Rejected for %s by %s' % (
          self.filename, current_user_nick)
    else:
      logging.warning('Unknown action in ProposalMailer: %s', action)
      return

    recipient_list = [self.user]
    recipient, _ = settings.Settings.GetItem('email_admin_list')
    if recipient:
      recipient_list.append(recipient)
    mail_tool.SendMail(recipient_list, subject, body)

  def _BuildProposalBody(self, hostname, filename):
    body = ''
    for key in self.COMMON_PROPERTIES:
      if getattr(self, key) != getattr(self.pkginfo, key):
        body += u'%s --> %s\n' % (
            getattr(self.pkginfo, key), getattr(self, key))

    hostname = urllib.quote(hostname)
    filename = urllib.quote(filename)
    body += '\nhttps://%s/admin/package/%s' % (hostname, filename)
    return body


def GetLockForPackage(filename):
  lock_name = PACKAGE_LOCK_PREFIX + filename
  lock = datastore_locks.DatastoreLock(lock_name)
  return lock
