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
"""Module to handle /pkgs"""

import httplib
import logging
import urllib

from google.appengine.api import memcache
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

from simian.mac import models
from simian.mac.common import auth
from simian.mac.munki import common
from simian.mac.munki import handlers


def PackageExists(filename):
  """Check whether a package exists.

  Args:
    filename: str, package filename like 'foo.dmg'
  Returns:
    True or False
  """
  return models.PackageInfo.get_by_key_name(filename) is not None


class Packages(
    handlers.AuthenticationHandler,
    blobstore_handlers.BlobstoreDownloadHandler):
  """Handler for /pkgs/"""

  def get(self, filename):
    """GET

    Args:
      filename: str, package filename like 'foo.dmg'
    Returns:
      None if a blob is being returned,
      or a response object
    """
    auth_return = auth.DoAnyAuth()
    if hasattr(auth_return, 'email'):
      email = auth_return.email()
      if not any((auth.IsAdminUser(email),
                  auth.IsSupportUser(email),
                 )):
        raise auth.IsAdminMismatch

    filename = urllib.unquote(filename)
    pkg = models.PackageInfo.MemcacheWrappedGet(filename)

    if pkg is None or not pkg.blobstore_key:
      self.error(httplib.NOT_FOUND)
      return

    if common.IsPanicModeNoPackages():
      self.error(httplib.SERVICE_UNAVAILABLE)
      return

    # Get the Blobstore BlobInfo for this package; memcache wrapped.
    memcache_key = 'blobinfo_%s' % filename
    blob_info = memcache.get(memcache_key)
    if not blob_info:
      blob_info = blobstore.BlobInfo.get(pkg.blobstore_key)
      if blob_info:
        memcache.set(memcache_key, blob_info, 300)  # cache for 5 minutes.
      else:
        logging.error(
            'Failure fetching BlobInfo for %s. Verify the blob exists: %s',
            pkg.filename, pkg.blobstore_key)
        self.error(httplib.NOT_FOUND)
        return

    header_date_str = self.request.headers.get('If-Modified-Since', '')
    etag_nomatch_str = self.request.headers.get('If-None-Match', 0)
    etag_match_str = self.request.headers.get('If-Match', 0)
    pkg_date = blob_info.creation
    pkg_size_bytes = blob_info.size

    # TODO(user): The below can be simplified once all of our clients
    # have ETag values set on the filesystem for these files.  The
    # parsing of If-Modified-Since could be removed.  Removing it prematurely
    # will cause a re-download of all packages on all clients for 1 iteration
    # until they all have ETag values.

    # Reduce complexity of elif conditional below.
    # If an If-None-Match: ETag is supplied, don't worry about a
    # missing file modification date -- the ETag supplies everything needed.
    if etag_nomatch_str and not header_date_str:
      resource_expired = False
    else:
      resource_expired = handlers.IsClientResourceExpired(
          pkg_date, header_date_str)

    # Client supplied If-Match: etag, but that etag does not match current
    # etag.  return 412.
    if (etag_match_str and pkg.pkgdata_sha256 and
        etag_match_str != pkg.pkgdata_sha256):
      self.response.set_status(412)

    # Client supplied no etag or If-No-Match: etag, and the etag did not
    # match, or the client's file is older than the mod time of this package.
    elif ((etag_nomatch_str and pkg.pkgdata_sha256 and
           etag_nomatch_str != pkg.pkgdata_sha256) or resource_expired):
      self.response.headers['Content-Disposition'] = str(
          'attachment; filename=%s' % filename)
      # header date empty or package has changed, send blob with last-mod date.
      if pkg.pkgdata_sha256:
        self.response.headers['ETag'] = str(pkg.pkgdata_sha256)
      self.response.headers['Last-Modified'] = pkg_date.strftime(
          handlers.HEADER_DATE_FORMAT)
      self.response.headers['X-Download-Size'] = str(pkg_size_bytes)
      self.send_blob(pkg.blobstore_key)
    else:
      # Client doesn't need to do anything, current version is OK based on
      # ETag and/or last modified date.
      if pkg.pkgdata_sha256:
        self.response.headers['ETag'] = str(pkg.pkgdata_sha256)
      self.response.set_status(httplib.NOT_MODIFIED)


class ClientRepair(Packages):
  """Handler for /repair/"""

  def get(self, client_id_str=''):
    """GET

    Returns:
      None if a blob is being returned,
      or a response object
    """
    session = auth.DoAnyAuth()
    client_id = handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str=client_id_str)

    logging.info('Repair client ID: %s', client_id)
    filename = None
    for pkg in models.PackageInfo.all().filter('name =', 'munkitools'):
      if client_id.get('track', '') in pkg.catalogs:
        filename = pkg.filename
        break

    if filename:
      logging.info('Sending client: %s', filename)
      super(ClientRepair, self).get(filename)
    else:
      logging.warning('No repair client found.')
