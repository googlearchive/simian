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

"""Module containing url handler for authsession_cleanup cron.

Classes:
  AuthSessionCleanup: the url handler
"""



import logging
import os
import time
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from simian.auth import gaeserver
from simian.mac import models


class AuthSessionCleanup(webapp.RequestHandler):
  """Class to invoke auth session cleanup routines when called."""

  def get(self):
    """Handle GET"""
    asd = gaeserver.AuthSessionSimianServer()
    expired_sessions_count = asd.ExpireAll()
    logging.debug(
        'AuthSessionCleanup: %d sessions expired.', expired_sessions_count)


class MarkComputersInactive(webapp.RequestHandler):
  """Class to mark all inactive hosts as such in Datastore."""

  def get(self):
    """Handle GET."""
    logging.debug('Marking inactive computers....')
    count = models.Computer.MarkInactive()
    logging.debug('Complete! Marked %s inactive.' % count)


class VerifyPackages(webapp.RequestHandler):
  """Class to verify all packages have matching Blobstore blobs."""

  def get(self):
    """Handle GET"""
    logging.debug('Verifying all PackageInfo and Blobstore Blobs....')
    pkginfo_count = 0
    for p in models.PackageInfo.all():
      blob_info = blobstore.BlobInfo.get(p.blobstore_key)
      if not blob_info:
        logging.critical('PackageInfo missing Blob: %s', p.filename)
      pkginfo_count +=1

    blob_count = 0
    for b in blobstore.BlobInfo.all():
      # Filter by blobstore_key as duplicate filenames are allowed in Blobstore.
      key = b.key()
      max_attempts = 5
      for i in xrange(1, max_attempts + 1):
        p = models.PackageInfo.all().filter('blobstore_key =', key).get()
        if p:
          break
        elif i == max_attempts:
          logging.critical('Orphaned Blob %s: %s', b.filename, key)
          break
        time.sleep(1)

      blob_count += 1
    logging.debug(
        'Verification of %d PackageInfo entities and %d Blobs complete.',
        pkginfo_count, blob_count)


application = webapp.WSGIApplication([
    ('/cron/maintenance/authsession_cleanup', AuthSessionCleanup),
    ('/cron/maintenance/mark_computers_inactive', MarkComputersInactive),
    ('/cron/maintenance/verify_packages', VerifyPackages),
])


def main():
  if os.environ.get('SERVER_SOFTWARE', '').startswith('Development'):
    logging.getLogger().setLevel(logging.DEBUG)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()
