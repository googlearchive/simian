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

"""Module to handle /pkgs"""



import logging
import urllib
from google.appengine.api import memcache
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from google.appengine.ext.webapp import blobstore_handlers
from simian.mac import models
from simian.auth import gaeserver
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
    auth.DoAnyAuth()
    filename = urllib.unquote(filename)
    pkg = models.PackageInfo.MemcacheWrappedGet(filename)

    if pkg is None or not pkg.blobstore_key:
      self.error(404)
      return

    if common.IsPanicModeNoPackages():
      self.error(503)
      return

    # Get the Blobstore BlobInfo for this package; memcache wrapped.
    memcache_key = 'blobinfo_%s' % filename
    blob_info = memcache.get(memcache_key)
    if not blob_info:
      blob_info = blobstore.BlobInfo.get(pkg.blobstore_key)
      if blob_info:
        memcache.set(memcache_key, blob_info, 300)  # cache for 5 minutes.
      else:
        logging.critical(
            'Failure fetching BlobInfo for %s. Verify the blob exists: %s',
            pkg.filename, pkg.blobstore_key)
        self.error(404)
        return

    header_date_str = self.request.headers.get('If-Modified-Since', '')
    pkg_date = blob_info.creation
    if handlers.IsClientResourceExpired(pkg_date, header_date_str):
      # header date empty or package has changed, send blob with last-mod date.
      self.response.headers['Last-Modified'] = pkg_date.strftime(
          handlers.HEADER_DATE_FORMAT)
      self.send_blob(pkg.blobstore_key)
    else:
      # If-Modified-Since and Blobstore pkg datetimes match, return 304.
      self.response.set_status(304)