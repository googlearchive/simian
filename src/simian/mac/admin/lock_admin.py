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
#

"""Lock Admin handler."""




from google.appengine.api import memcache

from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import gae_util

PACKAGE = 'package'
CATALOG = 'catalog'
MANIFEST = 'manifest'
LOCK_TYPES = {
    PACKAGE: gae_util.LOCK_NAME % 'pkgsinfo_%s',
    CATALOG: gae_util.LOCK_NAME % 'lock_catalog_%s',
    MANIFEST: gae_util.LOCK_NAME % 'lock_manifest_%s',
}


class LockAdmin(admin.AdminHandler):
  """Handler for /admin/lock_admin."""

  def post(self):
    """POST handler."""
    if not auth.IsAdminUser():
      return

    lock_type = self.request.get('lock_type')
    if lock_type not in LOCK_TYPES:
      self.error(404)
      return

    lock_name = self.request.get('lock_name')
    memcache.delete(LOCK_TYPES[lock_type] % lock_name)
    self.redirect('/admin/lock_admin?msg=Lock deleted successfully.')

  def get(self):
    """GET handler."""
    if not auth.IsAdminUser():
      return

    locks = []
    pkgs = [k.name() for k in models.PackageInfo.all(keys_only=True)]
    for pkg in pkgs:
      if memcache.get(LOCK_TYPES[PACKAGE] % pkg):
        locks.append((PACKAGE, pkg))

    for catalog in common.TRACKS:
      if memcache.get(LOCK_TYPES[CATALOG] % catalog):
        locks.append((CATALOG, catalog))

    for manifest in common.TRACKS:
      if memcache.get(LOCK_TYPES[MANIFEST] % manifest):
        locks.append((MANIFEST, manifest))

    values = {'report_type': 'lock_admin', 'locks': locks}
    self.Render('templates/lock_admin.html', values)