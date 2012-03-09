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

"""Module to handle /uploadpkg."""



import logging

from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.munki import handlers
from simian.mac.munki import plist as plist_lib
from simian.mac.munki.handlers import pkgs


class UploadPackage(
    handlers.AuthenticationHandler,
    blobstore_handlers.BlobstoreUploadHandler):
  """Handler for /uploadpkg"""

  def get(self):
    """GET

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
    if not handlers.IsHttps(self):
      # TODO(user): Does blobstore support https yet? If so, we can
      # enforce security in app.yaml and not do this check here.
      return

    gaeserver.DoMunkiAuth()

    mode = self.request.get('mode')
    msg = self.request.get('msg', None)
    if mode == 'success':
      self.response.out.write(self.request.get('key'))
    elif mode == 'error':
      self.response.set_status(400)
      self.response.out.write(msg)
    else:
      upload_url = blobstore.create_upload_url('/uploadpkg')
      self.response.out.write(upload_url)

  def post(self):
    """POST

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
          'POST to /uploadpkg not from Blobstore: %s', self.request.headers)
      self.redirect('/')

    gaeserver.DoMunkiAuth(require_level=gaeserver.LEVEL_UPLOADPKG)

    user = self.request.get('user')
    filename = self.request.get('name')
    install_types = self.request.get('install_types')
    catalogs = self.request.get('catalogs', None)
    manifests = self.request.get('manifests', None)
    if catalogs is None or not install_types or not user or not filename:
      msg = 'uploadpkg POST required parameters missing'
      logging.error(msg)
      self.redirect('/uploadpkg?mode=error&msg=%s' % msg)
      return
    if catalogs == '':
      catalogs = []
    else:
      catalogs = catalogs.split(',')
    if manifests in ['', None]:
      manifests = []
    else:
      manifests = manifests.split(',')
    install_types = install_types.split(',')

    upload_files = self.get_uploads('file')
    upload_pkginfo_files = self.get_uploads('pkginfo')
    if not len(upload_pkginfo_files) and not self.request.get('pkginfo'):
      self.redirect('/uploadpkg?mode=error&msg=No%20file%20received')
      return

    if len(upload_pkginfo_files):
      # obtain the pkginfo from a blob, and then throw it away.  this is
      # a necessary hack because the upload handler grabbed it, but we don't
      # intend to keep it in blobstore.
      pkginfo_str = gae_util.GetBlobAndDel(upload_pkginfo_files[0].key())
    else:
      # otherwise, grab the form parameter.
      pkginfo_str = self.request.get('pkginfo')

    blob_info = upload_files[0]
    blobstore_key = str(blob_info.key())

    # Parse, validate, and encode the pkginfo plist.
    plist = plist_lib.MunkiPackageInfoPlist(pkginfo_str)
    try:
      plist.Parse()
    except plist_lib.PlistError, e:
      logging.exception('Invalid pkginfo plist uploaded:\n%s\n', pkginfo_str)
      gae_util.SafeBlobDel(blobstore_key)
      self.redirect('/uploadpkg?mode=error&msg=No%20valid%20pkginfo%20received')
      return

    filename = plist['installer_item_location']
    pkgdata_sha256 = plist['installer_item_hash']

    # verify the blob was actually written; in case Blobstore failed to write
    # the blob but still POSTed to this handler (very, very rare).
    blob_info = blobstore.BlobInfo.get(blobstore_key)
    if not blob_info:
      logging.critical(
          'Blobstore returned a key for %s that does not exist: %s',
          filename, blobstore_key)
      self.redirect('/uploadpkg?mode=error&msg=Blobstore%20failure')
      return

    # Obtain a lock on the PackageInfo entity for this package.
    lock = 'pkgsinfo_%s' % filename
    if not gae_util.ObtainLock(lock, timeout=5.0):
      gae_util.SafeBlobDel(blobstore_key)
      self.redirect('/uploadpkg?mode=error&msg=Could%20not%20lock%20pkgsinfo')
      return

    old_blobstore_key = None
    pkg = models.PackageInfo.get_or_insert(filename)
    if not pkg.IsSafeToModify():
      gae_util.ReleaseLock(lock)
      gae_util.SafeBlobDel(blobstore_key)
      self.redirect('/uploadpkg?mode=error&msg=Package%20is%20not%20modifiable')
      return

    if pkg.blobstore_key:
      # a previous blob exists.  delete it when the update has succeeded.
      old_blobstore_key = pkg.blobstore_key

    pkg.blobstore_key = blobstore_key
    pkg.name = plist.GetPackageName()
    pkg.filename = filename
    pkg.user = user
    pkg.catalogs = catalogs
    pkg.manifests = manifests
    pkg.install_types = install_types
    pkg.plist = plist
    pkg.pkgdata_sha256 = pkgdata_sha256

    # update the PackageInfo model with the new plist string and blobstore key.
    try:
      pkg.put()
      success = True
    except db.Error:
      logging.exception('error on PackageInfo.put()')
      success = False

    # if it failed, delete the blob that was just uploaded -- it's
    # an orphan.
    if not success:
      gae_util.SafeBlobDel(blobstore_key)
      # if this is a new entity (get_or_insert puts), attempt to delete it.
      if not old_blobstore_key:
        gae_util.SafeEntityDel(pkg)
      gae_util.ReleaseLock(lock)
      self.redirect('/uploadpkg?mode=error')
      return

    # if an old blob was associated with this Package, delete it.
    # the new blob that was just uploaded has replaced it.
    if old_blobstore_key:
      gae_util.SafeBlobDel(old_blobstore_key)

    gae_util.ReleaseLock(lock)

    # Generate catalogs for newly uploaded pkginfo plist.
    for catalog in pkg.catalogs:
      models.Catalog.Generate(catalog, delay=1)

    # Log admin upload to Datastore.
    admin_log = models.AdminPackageLog(
        user=user, action='uploadpkg', filename=filename, catalogs=catalogs,
        manifests=manifests, install_types=install_types,
        plist=pkg.plist.GetXml())
    admin_log.put()

    self.redirect('/uploadpkg?mode=success&key=%s' % blobstore_key)