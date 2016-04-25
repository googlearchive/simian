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
"""PackagesInfo handlers."""

import hashlib
import logging
import urllib

from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import gae_util
from simian.mac.munki import handlers
from simian.mac.munki import plist
from simian.mac.munki.handlers import pkgs


class PackageDoesNotExistError(plist.PlistError):
  """The package referenced in the pkginfo plist does not exist."""


class MunkiPackageInfoPlistStrict(plist.MunkiPackageInfoPlist):
  """Class for Munki plist with added strict validation."""

  def __init__(self, *args, **kwargs):
    super(MunkiPackageInfoPlistStrict, self).__init__(*args, **kwargs)
    self.AddValidationHook(self.ValidatePackageExists)

  def ValidatePackageExists(self):
    """Verifies if a particular package exists or not."""
    if not pkgs.PackageExists(self._plist['installer_item_location']):
      raise PackageDoesNotExistError(
          'Package %s does not exist' % self._plist['installer_item_location'])


class PackagesInfo(handlers.AuthenticationHandler):
  """Handler for /pkgsinfo/"""

  def get(self, filename=None):
    """GET

    Args:
      filename: string like Firefox-1.0.dmg
    """
    auth_return = auth.DoAnyAuth()
    if hasattr(auth_return, 'email'):
      email = auth_return.email()
      if not any((auth.IsAdminUser(email),
                  auth.IsSupportUser(email),
                 )):
        raise auth.IsAdminMismatch

    if filename:
      filename = urllib.unquote(filename)
      hash_str = self.request.get('hash')

      if hash_str:
        lock = 'pkgsinfo_%s' % filename
        if not gae_util.ObtainLock(lock, timeout=5.0):
          self.response.set_status(403)
          self.response.out.write('Could not lock pkgsinfo')
          return

      pkginfo = models.PackageInfo.get_by_key_name(filename)
      if pkginfo:
        self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
        if hash_str:
          self.response.headers['X-Pkgsinfo-Hash'] = self._Hash(pkginfo.plist)
        self.response.out.write(pkginfo.plist)
      else:
        if hash_str:
          gae_util.ReleaseLock(lock)
        self.response.set_status(404)
        return

      if hash_str:
        gae_util.ReleaseLock(lock)
    else:
      query = models.PackageInfo.all()

      filename = self.request.get('filename')
      if filename:
        query.filter('filename', filename)

      install_types = self.request.get_all('install_types')
      for install_type in install_types:
        query.filter('install_types =', install_type)

      catalogs = self.request.get_all('catalogs')
      for catalog in catalogs:
        query.filter('catalogs =', catalog)

      pkgs = []
      for p in query:
        pkg = {}
        for k in p.properties():
          if k != '_plist':
            pkg[k] = getattr(p, k)
        pkgs.append(pkg)
      self.response.out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
      self.response.out.write(plist.GetXmlStr(pkgs))
      self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'

  def _Hash(self, s):
    """Return a sha256 hash for a string.

    Args:
      s: str
    Returns:
      str, sha256 digest
    """
    h = hashlib.sha256(str(s))
    return h.hexdigest()

  def put(self, filename):
    """PUT

    Args:
      filename: string like Firefox-1.0.dmg
    """
    session = gaeserver.DoMunkiAuth(require_level=gaeserver.LEVEL_UPLOADPKG)

    filename = urllib.unquote(filename)
    hash_str = self.request.get('hash')
    catalogs = self.request.get('catalogs', None)
    manifests = self.request.get('manifests', None)
    install_types = self.request.get('install_types')

    if catalogs == '':
      catalogs = []
    elif catalogs:
      catalogs = catalogs.split(',')
    if manifests == '':
      manifests = []
    elif manifests:
      manifests = manifests.split(',')
    if install_types:
      install_types = install_types.split(',')

    mpl = MunkiPackageInfoPlistStrict(self.request.body)
    try:
      mpl.Parse()
    except plist.PlistError, e:
      logging.exception('Invalid pkginfo plist PUT: \n%s\n', self.request.body)
      self.response.set_status(400)
      self.response.out.write(str(e))
      return

    lock = 'pkgsinfo_%s' % filename
    if not gae_util.ObtainLock(lock, timeout=5.0):
      self.response.set_status(403)
      self.response.out.write('Could not lock pkgsinfo')
      return

    # To avoid pkginfo uploads without corresponding packages, only allow
    # updates to existing PackageInfo entities, not creations of new ones.
    pkginfo = models.PackageInfo.get_by_key_name(filename)
    if pkginfo is None:
      logging.warning(
          'pkginfo "%s" does not exist; PUT only allows updates.', filename)
      self.response.set_status(403)
      self.response.out.write('Only updates supported')
      gae_util.ReleaseLock(lock)
      return

    # If the pkginfo is not modifiable, ensure only manifests have changed.
    if not pkginfo.IsSafeToModify():
      if not mpl.EqualIgnoringManifestsAndCatalogs(pkginfo.plist):
        logging.warning(
            'pkginfo "%s" is in stable or testing; change prohibited.',
            filename)
        self.response.set_status(403)
        self.response.out.write('Changes to pkginfo not allowed')
        gae_util.ReleaseLock(lock)
        return

    # If the update parameter asked for a careful update, by supplying
    # a hash of the last known pkgsinfo, then compare the hash to help
    # the client make a non destructive update.
    if hash_str:
      if self._Hash(pkginfo.plist) != hash_str:
        self.response.set_status(409)
        self.response.out.write('Update hash does not match')
        gae_util.ReleaseLock(lock)
        return

    # All verification has passed, so let's create the PackageInfo entity.
    pkginfo.plist = mpl
    pkginfo.name = mpl.GetPackageName()
    if catalogs is not None:
      pkginfo.catalogs = catalogs
    if manifests is not None:
      pkginfo.manifests = manifests
    if install_types:
      pkginfo.install_types = install_types
    pkginfo.put()

    gae_util.ReleaseLock(lock)

    for track in pkginfo.catalogs:
      models.Catalog.Generate(track, delay=1)

    # Log admin pkginfo put to Datastore.
    user = session.uuid
    admin_log = models.AdminPackageLog(
        user=user, action='pkginfo', filename=filename,
        catalogs=pkginfo.catalogs, manifests=pkginfo.manifests,
        install_types=pkginfo.install_types, plist=pkginfo.plist.GetXml())
    admin_log.put()
