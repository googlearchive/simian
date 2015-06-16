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
#
#

"""Module to handle /deletepkg."""




import logging

from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.munki import handlers


class DeletePackage(handlers.AuthenticationHandler):
  """Handler for /deletepkg"""

  def post(self):
    """POST

    Parameters:
      filename: filename of package e.g. 'Firefox-1.0.dmg'
    """
    session = gaeserver.DoMunkiAuth(require_level=gaeserver.LEVEL_UPLOADPKG)

    filename = self.request.get('filename')
    pkginfo = models.PackageInfo.get_by_key_name(filename)
    if not pkginfo:
      self.response.set_status(404)
      self.response.out.write('Pkginfo does not exist: %s' % filename)
      return

    plist = pkginfo.plist
    catalogs = pkginfo.catalogs
    install_types = pkginfo.install_types

    #logging.info('Deleting package: %s', filename)
    blobstore_key = pkginfo.blobstore_key
    # Delete the PackageInfo entity, and then the package Blobstore entity.
    pkginfo.delete()
    gae_util.SafeBlobDel(blobstore_key)
    # Recreate catalogs so references to this package don't exist anywhere.
    for catalog in catalogs:
      models.Catalog.Generate(catalog)

    # Log admin delete to Datastore.
    user = session.uuid
    admin_log = models.AdminPackageLog(
        user=user, action='deletepkg', filename=filename, catalogs=catalogs,
        install_types=install_types, plist=plist)
    admin_log.put()

    #logging.info(
    #    'PackageInfo and Package Blob deleted successfully: %s', filename)
