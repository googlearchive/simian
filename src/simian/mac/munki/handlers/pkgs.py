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



import datetime
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


HEADER_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'


def PackageExists(filename):
  """Check whether a package exists.

  Args:
    filename: str, package filename like 'foo.dmg'
  Returns:
    True or False
  """
  return models.PackageInfo.get_by_key_name(filename) is not None


def IsPackageModifiedSince(pkg_date, header_date):
  """Compares a If-Modified-Since header date to Blobstore pkg date.

  Args:
    pkg_date: datetime when the pkg was last modified.
    header_date: str date value like "Wed, 06 Oct 2010 03:23:34 GMT".
  Returns:
    Boolean. True if the pkg was modified after header date, False otherwise.
  """
  if not header_date:
    return True

  try:
    # NOTE(user): strptime is a py2.5+ feature.
    header_date = datetime.datetime.strptime(header_date, HEADER_DATE_FORMAT)
  except ValueError:
    logging.exception(
        'Error parsing If-Modified-Since date: %s', header_date)
    return True

  # if pkg date and header date are the same (disregarding ms) then not modified
  if pkg_date.replace(microsecond=0) == header_date:
    return False
  else:
    # this should be very rare - pkg changed in between munki runs - so log it.
    logging.debug(
      '/pkg/ download date compare: pkg %s != header %s',
      pkg_date.replace(microsecond=0), header_date)
    return True


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
    if IsPackageModifiedSince(pkg_date, header_date_str):
      # header date empty or package has changed, send blob with last-mod date.
      self.response.headers['Last-Modified'] = pkg_date.strftime(
          HEADER_DATE_FORMAT)
      self.send_blob(pkg.blobstore_key)
    else:
      # If-Modified-Since and Blobstore pkg datetimes match, return 304.
      self.response.set_status(304)