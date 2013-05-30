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




import datetime
import logging
import os
import re
import time
import webapp2

from google.appengine.api import mail
from google.appengine.ext import blobstore

from simian import settings
from simian.auth import gaeserver
from simian.mac import common
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.munki import plist


class AuthSessionCleanup(webapp2.RequestHandler):
  """Class to invoke auth session cleanup routines when called."""

  def get(self):
    """Handle GET"""
    asd = gaeserver.AuthSessionSimianServer()
    expired_sessions_count = asd.ExpireAll()
    #logging.debug(
    #    'AuthSessionCleanup: %d sessions expired.', expired_sessions_count)


class MarkComputersInactive(webapp2.RequestHandler):
  """Class to mark all inactive hosts as such in Datastore."""

  def get(self):
    """Handle GET."""
    #logging.debug('Marking inactive computers....')
    count = models.Computer.MarkInactive()
    #logging.debug('Complete! Marked %s inactive.' % count)


class UpdateAverageInstallDurations(webapp2.RequestHandler):
  """Class to update average install duration pkginfo descriptions reguarly."""

  def get(self):
    """Handle GET."""
    pkgs, unused_dt = models.ReportsCache.GetInstallCounts()

    for p in models.PackageInfo.all():
      if not p.plist:
        continue  # skip over pkginfos without plists.

      if p.munki_name not in pkgs:
        # Skip pkginfos that ReportsCache lacks.
        continue
      elif not pkgs[p.munki_name].get('duration_seconds_avg', None):
        # Skip pkginfos where there is no known average duration.
        continue

      # Obtain a lock on the PackageInfo entity for this package, or skip.
      lock = 'pkgsinfo_%s' % p.filename
      if not gae_util.ObtainLock(lock, timeout=5.0):
        continue  # Skip; it'll get updated next time around.

      # Append the avg duration text to the description; in the future the
      # avg duration time and overall install count will be added to they're
      # own pkginfo keys so the information can be displayed independantly.
      # This requires MSU changes to read and display such values, so for now
      # simply append text to the description.
      old_desc = p.plist['description']
      avg_duration_text = models.PackageInfo.AVG_DURATION_TEXT % (
          pkgs[p.munki_name]['duration_count'],
          pkgs[p.munki_name]['duration_seconds_avg'])
      p.description = '%s\n\n%s' % (p.description, avg_duration_text)
      if p.plist['description'] != old_desc:
        p.put()  # Only bother putting the entity if the description changed.
      gae_util.ReleaseLock(lock)

    # Asyncronously regenerate all Catalogs to include updated pkginfo plists.
    delay = 0
    for track in common.TRACKS:
      delay += 5
      models.Catalog.Generate(track, delay=delay)


class VerifyPackages(webapp2.RequestHandler):
  """Class to verify all packages have matching Blobstore blobs."""

  def get(self):
    """Handle GET."""
    # Verify that all PackageInfo entities older than a week have a file in
    # Blobstore.
    for p in models.PackageInfo.all():
      if p.blobstore_key and blobstore.BlobInfo.get(p.blobstore_key):
        continue
      elif p.mtime < (datetime.datetime.utcnow() - datetime.timedelta(days=7)):
        m = mail.EmailMessage()
        m.to = [settings.EMAIL_ADMIN_LIST]
        m.sender = settings.EMAIL_SENDER
        m.subject = 'Package is lacking a file: %s' % p.filename
        m.body = (
            'The following package is lacking a DMG file: \n'
            'https://%s/admin/package/%s' % (
                settings.SERVER_HOSTNAME, p.filename))
        m.send()

    # Verify all Blobstore Blobs have associated PackageInfo entities.
    for b in blobstore.BlobInfo.all():
      # Filter by blobstore_key as duplicate filenames are allowed in Blobstore.
      key = b.key()
      max_attempts = 5
      for i in xrange(1, max_attempts + 1):
        p = models.PackageInfo.all().filter('blobstore_key =', key).get()
        if p:
          break
        elif i == max_attempts:
          m = mail.EmailMessage()
          m.to = [settings.EMAIL_ADMIN_LIST]
          m.sender = settings.EMAIL_SENDER
          m.subject = 'Orphaned Blob in Blobstore: %s' % b.filename
          m.body = (
              'An orphaned Blob exists in Blobstore. Use App Engine Admin '
              'Console\'s "Blob Viewer" to locate and delete this Blob.\n\n'
              'Filename: %s\nBlobstore Key: %s' % (b.filename, key))
          m.send()
          break
        time.sleep(1)
