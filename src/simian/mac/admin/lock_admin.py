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
"""Lock Admin handler."""

import httplib

from simian.mac.common import datastore_locks
from simian.mac import admin
from simian.mac import models

_PACKAGE = 'package'


def _ListAllLockedPackages():
  """List all active locks for packages."""
  # pylint: disable=protected-access
  # pylint: disable=g-explicit-bool-comparison
  locks = datastore_locks._DatastoreLockEntity.query(
      datastore_locks._DatastoreLockEntity.acquired == True).fetch()
  # pylint: enable=protected-access
  # pylint: enable=g-explicit-bool-comparison

  locked_pkgs = []
  for l in locks:
    if l.lock_held and l.key.id().startswith(models.PACKAGE_LOCK_PREFIX):
      locked_pkgs.append(l.key.id()[len(models.PACKAGE_LOCK_PREFIX):])
  return locked_pkgs


def _ForceReleaseLock(pkg_name):
  lock_name = models.PACKAGE_LOCK_PREFIX + pkg_name
  e = datastore_locks._DatastoreLockEntity.get_by_id(lock_name)  # pylint: disable=protected-access
  e.acquired = False
  e.put()


class LockAdmin(admin.AdminHandler):
  """Handler for /admin/lock_admin."""

  @admin.AdminHandler.XsrfProtected('lock_admin')
  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return

    if self.request.get('lock_type') != _PACKAGE:
      self.error(httplib.BAD_REQUEST)
      return

    pkg_name = self.request.get('lock_name')
    _ForceReleaseLock(pkg_name)

    self.redirect('/admin/lock_admin?msg=Lock deleted successfully.')

  def get(self):
    """GET handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return

    locks = []
    for pkg in _ListAllLockedPackages():
      locks.append((_PACKAGE, pkg))

    values = {'report_type': 'lock_admin', 'locks': locks}
    self.Render('lock_admin.html', values)
