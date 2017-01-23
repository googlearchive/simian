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
"""Module to handle /admin/uploadpkg."""

import base64
import hashlib
import httplib

from simian.mac.common import datastore_locks
import cloudstorage as gcs
from simian import settings
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth


def GetIconGCSPath(pkg):
  """Get the icon for package."""
  try:
    bucket = settings.ICONS_GCS_BUCKET
  except AttributeError:
    return ''
  if not pkg.name:
    return ''

  icon_path = '/%s/%s.png' % (
      bucket, base64.urlsafe_b64encode(pkg.name))
  try:
    with gcs.open(icon_path, 'r'):
      return icon_path
  except gcs.NotFoundError:
    return ''


class UploadIcon(admin.AdminHandler):
  """Handler for /admin/upload_icon."""

  def _RenderError(self, status_code, msg):
    self.Render('error.html', {'message': msg})
    self.response.set_status(status_code)

  @admin.AdminHandler.XsrfProtected('package')
  def post(self, filename):
    auth.DoUserAuth()

    try:
      bucket = settings.ICONS_GCS_BUCKET
    except AttributeError:
      self._RenderError(
          httplib.NOT_FOUND, 'Dedicated icons GCS bucket is not set.')
      return

    p = models.PackageInfo.get_by_key_name(filename)
    if not p:
      self._RenderError(
          httplib.NOT_FOUND, 'PackageInfo not found: %s' % filename)
      return
    if not p.name:
      self._RenderError(
          httplib.NOT_FOUND, 'PackageInfo Name is empty: %s' % filename)
      return

    icon_filename = self.request.POST['icon'].filename
    if not icon_filename.endswith('.png'):
      self._RenderError(
          httplib.BAD_REQUEST, 'Only png icons supported.')
      return

    lock = models.GetLockForPackage(p.filename)
    try:
      lock.Acquire()
    except datastore_locks.AcquireLockError:
      self._RenderError(httplib.CONFLICT, 'PackageInfo is locked')
      return

    content = self.request.POST['icon'].file.read()

    icon_path = '/%s/%s.png' % (
        bucket, base64.urlsafe_b64encode(p.name))
    with gcs.open(icon_path, 'w') as f:
      f.write(content)

    plist = p.plist
    plist['icon_hash'] = hashlib.sha256(content).hexdigest()

    # replace p._plist
    p.plist = str(plist)

    p.put()

    lock.Release()

    for catalog in p.catalogs:
      models.Catalog.Generate(catalog)

    self.redirect('/admin/package/%s' % filename)
