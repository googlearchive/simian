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
"""Manifest Modifications admin handler."""

import json

from google.appengine.api import users
from google.appengine.ext import db

from simian import settings
from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import gae_util

MAX_TARGETS_PER_POST = 70

# Manifest Modification Type key/value pairs, where the key is used for
# form field and query parameter naming, and the value is for human readable
# UI friendliness.
MOD_TYPES = (
    ('owner', 'Owner'),
    ('uuid', 'UUID'),
    ('site', 'Site'),
    ('os_version', 'OS Version'),
    ('tag', 'Tag'),
)
# A dictionary of the allowed manifest modification types for each group.
MOD_GROUP_TYPES = {
    common.MANIFEST_MOD_SUPPORT_GROUP: MOD_TYPES[:1],
    common.MANIFEST_MOD_SECURITY_GROUP: MOD_TYPES[:2],
}

DEFAULT_MANIFEST_MOD_FETCH_LIMIT = 25


class ManifestModifications(admin.AdminHandler):
  """Handler for /admin/manifest_modifications."""

  def post(self):
    """POST handler."""
    if self.request.get('add_manifest_mod'):
      if (not self.IsAdminUser() and
          not auth.IsSupportUser() and
          not auth.IsSecurityUser()):
        self.response.set_status(403)
        return
      self._AddManifestModification()
    elif self.IsAdminUser() and self.request.get('delete'):
      self._DeleteManifestModification()
    elif self.IsAdminUser() and self.request.get('enabled'):
      self._ToggleManifestModification()
    else:
      if not self.IsAdminUser():
        self.response.set_status(403)
        return
      self.response.set_status(404)

  def _AddManifestModification(self):
    """Adds a new manifest modification to Datastore."""
    mod_type = self.request.get('mod_type')
    targets = [x.strip() for x in self.request.get('target').split(',')
               if x.strip()]
    munki_pkg_name = self.request.get('munki_pkg_name').strip()
    manifests = self.request.get_all('manifests')
    install_types = self.request.get_all('install_types')
    remove_from_manifest = bool(self.request.get('remove-from-manifest'))

    # Security users are only able to inject specific packages.
    if not self.IsAdminUser():
      grp = None
      if auth.IsSupportUser():
        grp = common.MANIFEST_MOD_SUPPORT_GROUP
        # Support users can only inject items into optional_installs.
        install_types = ['optional_installs']
      elif auth.IsSecurityUser():
        grp = common.MANIFEST_MOD_SECURITY_GROUP
        # Security users can only inject items into managed_installs.
        install_types = ['managed_installs']

      munki_pkg_names = models.PackageInfo.GetManifestModPkgNames(
          grp, only_names=True)
      if munki_pkg_name not in munki_pkg_names:
        self.response.out.write(
            'You are not allowed to inject: %s' % munki_pkg_name)
        self.response.set_status(403)
        return
      elif mod_type not in [k for k, _ in MOD_GROUP_TYPES.get(grp, [])]:
        self.response.out.write(
            'You are not allowed to inject to: %s' % mod_type)
        self.response.set_status(403)
        return

    # Validation.
    error_msg = None
    if not targets or not munki_pkg_name or not install_types:
      error_msg = (
          'target, munki_pkg_name, and install_types are all required')
    if not error_msg:
      for manifest in manifests:
        if manifest not in common.TRACKS:
          error_msg = 'manifest %s is not in %s' % (manifest, common.TRACKS)
    if not error_msg:
      for install_type in install_types:
        if install_type not in common.INSTALL_TYPES:
          error_msg = 'install_type %s is not in %s' % (
              install_type, common.INSTALL_TYPES)
    if not error_msg:
      if not models.PackageInfo.all().filter('name =', munki_pkg_name).get():
        error_msg = 'No package found with Munki name: %s' % munki_pkg_name
    if not error_msg and len(targets) > MAX_TARGETS_PER_POST:
      error_msg = 'too many targets'
    if error_msg:
      self.redirect('/admin/manifest_modifications?msg=%s' % error_msg)
      return

    to_put = []
    for target in targets:
      mod = models.BaseManifestModification.GenerateInstance(
          mod_type, target, munki_pkg_name, manifests=manifests,
          install_types=install_types, user=users.get_current_user(),
          remove=remove_from_manifest)
      to_put.append(mod)

    gae_util.BatchDatastoreOp(db.put, to_put)
    for target in targets:
      models.BaseManifestModification.ResetModMemcache(mod_type, target)

    msg = 'Manifest Modification successfully saved.'
    self.redirect(
        '/admin/manifest_modifications?mod_type=%s&msg=%s' % (mod_type, msg))

  def _DeleteManifestModification(self):
    """Deletes a manifest modifications."""
    key_str = self.request.get('key')
    db.delete(db.Key(key_str))
    data = {'deleted': True, 'key': key_str}
    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(data))

  def _ToggleManifestModification(self):
    """Toggles manifest modifications between enabled and disabled."""
    key_str = self.request.get('key')
    enabled = self.request.get('enabled') == '1'
    mod = db.get(db.Key(key_str))
    mod.enabled = enabled
    mod.put()
    data = {'enabled': enabled, 'key': key_str}
    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(data))

  def get(self, report=None, product_id=None):
    """GET handler."""
    auth.DoUserAuth()
    self._DisplayMain()

  def _DisplayMain(self):
    """Displays the main Manifest Modification report."""
    error_msg = self.request.get('error')

    mod_type = self.request.get('mod_type') or 'owner'
    model = models.MANIFEST_MOD_MODELS.get(mod_type)
    if mod_type and not model:
      error_msg = 'Unknown mod_type provided; defaulting to owner'
      mod_type = 'owner'
      model = models.MANIFEST_MOD_MODELS.get(mod_type)

    mods_query = model.all().order('-mtime')

    filter_value = self.request.get('filter_value')
    filter_field = self.request.get('filter_field')
    if filter_value:
      if filter_field == 'target':
        mods_query.filter(model.TARGET_PROPERTY_NAME, filter_value)
      elif filter_field == 'package':
        mods_query.filter('value', filter_value)
      elif filter_field == 'admin':
        if '@' not in filter_value:
          filter_value += '@' + settings.AUTH_DOMAIN
        mods_query.filter('user', users.User(email=filter_value))

    mods = self.Paginate(mods_query, DEFAULT_MANIFEST_MOD_FETCH_LIMIT)

    is_admin = self.IsAdminUser()
    is_support = False
    is_security = False
    if not is_admin:
      is_support = auth.IsSupportUser()
      if not is_support:
        is_security = auth.IsSecurityUser()
    if is_admin:
      munki_pkg_names = models.PackageInfo.GetManifestModPkgNames(
          common.MANIFEST_MOD_ADMIN_GROUP)
      mod_types = MOD_TYPES
    elif is_support:
      munki_pkg_names = models.PackageInfo.GetManifestModPkgNames(
          common.MANIFEST_MOD_SUPPORT_GROUP)
      mod_types = MOD_GROUP_TYPES[common.MANIFEST_MOD_SUPPORT_GROUP]
    elif is_security:
      munki_pkg_names = models.PackageInfo.GetManifestModPkgNames(
          common.MANIFEST_MOD_SECURITY_GROUP)
      mod_types = MOD_GROUP_TYPES[common.MANIFEST_MOD_SECURITY_GROUP]
    else:
      munki_pkg_names = None
      mod_types = []

    data = {
        'mod_types': mod_types,
        'mod_type': mod_type,
        'mods': mods,
        'error': error_msg,
        'can_add_manifest_mods': is_admin or is_support or is_security,
        'munki_pkg_names': munki_pkg_names,
        'install_types': common.INSTALL_TYPES,
        'manifests': common.TRACKS,
        'report_type': 'manifests_admin',
        'mods_filter': filter_field,
        'mods_filter_value': filter_value,
    }
    self.Render('manifest_modifications.html', data)
