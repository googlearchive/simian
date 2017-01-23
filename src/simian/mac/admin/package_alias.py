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
"""Package Alias admin handler."""

import httplib
import json

from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import auth


class PackageAlias(admin.AdminHandler):
  """Handler for /admin/package_alias."""

  @admin.AdminHandler.XsrfProtected('manifests_aliases')
  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.response.set_status(httplib.FORBIDDEN)
      return

    if self.request.get('create_package_alias'):
      self._CreatePackageAlias()
    elif self.request.get('enabled'):
      self._TogglePackageAlias()
    else:
      self.response.set_status(httplib.NOT_FOUND)

  def _CreatePackageAlias(self):
    """Creates a new or edits an existing package alias, with verification."""
    package_alias = self.request.get('package_alias').strip()
    munki_pkg_name = self.request.get('munki_pkg_name').strip()

    if not package_alias:
      msg = 'Package Alias is required.'
      self.redirect('/admin/package_alias?msg=%s' % msg)
      return

    if not munki_pkg_name:
      munki_pkg_name = None
    elif not models.PackageInfo.all().filter('name =', munki_pkg_name).get():
      msg = 'Munki pkg %s does not exist.' % munki_pkg_name
      self.redirect('/admin/package_alias?msg=%s' % msg)
      return

    alias = models.PackageAlias(
        key_name=package_alias, munki_pkg_name=munki_pkg_name)
    if not munki_pkg_name:
      alias.enabled = False
    alias.put()
    msg = 'Package Alias successfully saved.'
    self.redirect('/admin/package_alias?msg=%s' % msg)

  def _TogglePackageAlias(self):
    """Sets an existing PackageAlias as enabled/disabled."""
    key_name = self.request.get('key_name')
    enabled = self.request.get('enabled') == '1'
    alias = models.PackageAlias.get_by_key_name(key_name)
    alias.enabled = enabled
    alias.put()
    data = {'enabled': enabled, 'key_name': key_name}
    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(data))

  def get(self, report=None, product_id=None):
    """GET handler."""
    auth.DoUserAuth()
    self._DisplayMain()

  def _DisplayMain(self):
    """Displays the main Package Alias report."""
    package_aliases = models.PackageAlias.all()
    is_admin = self.IsAdminUser()
    # TODO(user): generate PackageInfo dict so admin select box can use display
    #             names, munki package names can link to installs, etc.
    if is_admin:
      munki_pkg_names = models.PackageInfo.GetManifestModPkgNames(
          common.MANIFEST_MOD_ADMIN_GROUP)
    else:
      munki_pkg_names = None

    data = {
        'package_aliases': package_aliases,
        'munki_pkg_names': munki_pkg_names,
        'report_type': 'manifests_aliases',
    }
    self.Render('package_alias.html', data)
