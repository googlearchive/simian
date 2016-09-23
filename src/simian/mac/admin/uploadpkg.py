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
"""Module to handle /admin/uploadpkg."""

import httplib
import logging

from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import db
from google.appengine.ext.webapp import blobstore_handlers

from simian.mac.common import datastore_locks
from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth
from simian.mac.common import gae_util
from simian.mac.common import util
from simian.mac.munki import handlers


class UploadPackage(
    admin.AdminHandler,
    blobstore_handlers.BlobstoreUploadHandler):
  """Handler for /admin/uploadpkg."""

  XSRF_PROTECTION = False

  def get(self):
    """GET Handler.

    With no parameters, return the URL to use to submit uploads via
    multipart/form-data.

    With mode and key parameters, return status of the previous uploadpkg
    operation to the calling client.

    This method actually acts as a helper to the starting and finishing
    of the uploadpkg post() method.

    Parameters:
      mode: optionally, 'success' or 'error'
      key: optionally, blobstore key that was uploaded
    """
    if not auth.HasPermission(auth.UPLOAD):
      self.error(httplib.FORBIDDEN)
      return

    mode = self.request.get('mode')
    msg = self.request.get('msg', None)
    if mode == 'success':
      filename = self.request.get('filename')
      msg = '%s successfully uploaded and is ready for deployment.' % filename
      self.redirect('/admin/package/%s?msg=%s' % (filename, msg))
    elif mode == 'error':
      self.response.set_status(httplib.BAD_REQUEST)
      self.response.out.write(msg)
    else:
      filename = self.request.get('filename')
      if not filename:
        self.response.set_status(httplib.NOT_FOUND)
        self.response.out.write('Filename required')
        return

      p = models.PackageInfo.get_by_key_name(filename)
      if not p:
        self.response.set_status(httplib.BAD_REQUEST)
        self.response.out.write(
            'You must first upload a pkginfo for %s' % filename)
        return
      elif p.blob_info:
        self.response.set_status(httplib.BAD_REQUEST)
        self.response.out.write('This file already exists.')
        return

      upload_url = blobstore.create_upload_url(
          '/admin/uploadpkg', gs_bucket_name=util.GetBlobstoreGSBucket())

      values = {
          'upload_url': upload_url,
          'filename': filename,
          'file_size_kbytes': p.plist['installer_item_size'],
      }
      self.Render('upload_pkg_form.html', values)

  def _RedirectWithErrorMsg(self, msg):
    logging.warning(msg)
    self.redirect(
        '/admin/uploadpkg?mode=error&msg=%s' % msg)

  def post(self):
    """POST Handler.

    This method behaves a little strangely.  BlobstoreUploadHandler
    only allows returns statuses of 301, 302, 303 (not even 200), so
    one must redirect away to return more information to the caller.

    Parameters:
      file: package file contents
      pkginfo: packageinfo file contents
      name: filename of package e.g. 'Firefox-1.0.dmg'
    """
    # Only blobstore/upload service/scotty requests should be
    # invoking this handler.
    if not handlers.IsBlobstore():
      logging.critical(
          'POST to uploadpkg not from Blobstore: %s', self.request.headers)
      self.redirect('/admin/packages')
      return

    if not self.get_uploads('file'):
      logging.error('Upload package does not exist.')
      return

    blob_info = self.get_uploads('file')[0]
    blobstore_key = str(blob_info.key())

    # Obtain a lock on the PackageInfo entity for this package.
    lock = models.GetLockForPackage(blob_info.filename)
    try:
      lock.Acquire(timeout=30, max_acquire_attempts=5)
    except datastore_locks.AcquireLockError:
      gae_util.SafeBlobDel(blobstore_key)

      self._RedirectWithErrorMsg('PackageInfo is locked')
      return

    p = models.PackageInfo.get_by_key_name(blob_info.filename)
    if not p:
      lock.Release()
      gae_util.SafeBlobDel(blobstore_key)

      self._RedirectWithErrorMsg('PackageInfo not found')
      return

    if not p.IsSafeToModify():
      lock.Release()
      gae_util.SafeBlobDel(blobstore_key)

      self._RedirectWithErrorMsg('PackageInfo is not modifiable')
      return

    installer_item_size = p.plist['installer_item_size']
    size_difference = int(blob_info.size / 1024) - installer_item_size
    if abs(size_difference) > 1:
      lock.Release()
      gae_util.SafeBlobDel(blobstore_key)
      msg = 'Blob size (%s) does not match PackageInfo plist size (%s)' % (
          blob_info.size, installer_item_size)

      self._RedirectWithErrorMsg(msg)
      return

    old_blobstore_key = None
    if p.blobstore_key:
      # a previous blob exists.  delete it when the update has succeeded.
      old_blobstore_key = p.blobstore_key

    p.blob_info = blob_info

    # update the PackageInfo model with the new plist string and blobstore key.
    try:
      p.put()
      error = None
    except db.Error, e:
      logging.exception('error on PackageInfo.put()')
      error = 'pkginfo.put() failed with: %s' % str(e)

    # if it failed, delete the blob that was just uploaded -- it's
    # an orphan.
    if error is not None:
      gae_util.SafeBlobDel(blobstore_key)
      lock.Release()

      self._RedirectWithErrorMsg(error)
      return

    # if an old blob was associated with this Package, delete it.
    # the new blob that was just uploaded has replaced it.
    if old_blobstore_key:
      gae_util.SafeBlobDel(old_blobstore_key)

    lock.Release()

    user = users.get_current_user().email()
    # Log admin upload to Datastore.
    admin_log = models.AdminPackageLog(
        user=user, action='uploadpkg', filename=blob_info.filename)
    admin_log.put()


    self.redirect(
        '/admin/uploadpkg?mode=success&filename=%s' % blob_info.filename)
