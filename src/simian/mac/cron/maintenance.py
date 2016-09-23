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
"""Module containing url handler for authsession_cleanup cron.

Classes:
  AuthSessionCleanup: the url handler
"""

import datetime
import logging
import time
import uuid

import webapp2

from google.appengine.ext import blobstore
from google.appengine.ext import deferred

from simian.mac.common import datastore_locks
from simian import settings
from simian.auth import base as auth_base
from simian.auth import gaeserver
from simian.mac import common
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.common import mail


class AuthSessionCleanup(webapp2.RequestHandler):
  """Class to invoke auth session cleanup routines when called."""

  @classmethod
  def _DeferRemoveExpiredAuthSessions(
      cls, prefix, level, min_age_seconds, cursor=None):
    deferred_name = '%s_auth_session_cleanup_%s' % (prefix, str(uuid.uuid1()))
    deferred.defer(
        cls._RemoveExpiredAuthSessions, prefix, level, min_age_seconds,
        cursor, _name=deferred_name)

  @classmethod
  def _RemoveExpiredAuthSessions(cls, prefix, level, min_age_seconds, cursor):
    """Expire all session data."""
    asd = gaeserver.AuthSessionSimianServer()

    query = asd.All(level=level, min_age_seconds=min_age_seconds, cursor=cursor)
    sessions = query.fetch(settings.ENTITIES_PER_DEFERRED_TASK)

    if not sessions:
      return

    # expire all certs that are over min expiration age.
    for session in sessions:
      if asd.IsExpired(session):
        session.delete()

    cls._DeferRemoveExpiredAuthSessions(
        prefix, level, min_age_seconds, cursor=query.cursor())

  def get(self):
    """Handle GET"""
    for lvl in gaeserver.ALL_LEVELS:
      if lvl != gaeserver.LEVEL_APPLESUS:
        self._DeferRemoveExpiredAuthSessions(
            'token', lvl, auth_base.AGE_CN_SECONDS)

    self._DeferRemoveExpiredAuthSessions(
        'applesus', gaeserver.LEVEL_APPLESUS,
        auth_base.AGE_APPLESUS_TOKEN_SECONDS)


class MarkComputersInactive(webapp2.RequestHandler):
  """Class to mark all inactive hosts as such in Datastore."""

  def get(self):
    """Handle GET."""
    count = models.Computer.MarkInactive()
    logging.info('Complete! Marked %s inactive.', count)


class UpdateAverageInstallDurations(webapp2.RequestHandler):
  """Class to update average install duration pkginfo descriptions reguarly."""

  def get(self):
    """Handle GET."""
    pkgs, unused_dt = models.ReportsCache.GetInstallCounts()

    for p in gae_util.QueryIterator(models.PackageInfo.all()):
      if not p.plist:
        continue  # skip over pkginfos without plists.

      if p.munki_name not in pkgs:
        # Skip pkginfos that ReportsCache lacks.
        continue
      elif not pkgs[p.munki_name].get('duration_seconds_avg', None):
        # Skip pkginfos where there is no known average duration.
        continue

      # Obtain a lock on the PackageInfo entity for this package, or skip.
      lock = models.GetLockForPackage(p.filename)
      try:
        lock.Acquire(timeout=600, max_acquire_attempts=5)
      except datastore_locks.AcquireLockError:
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
        p.put(avoid_mtime_update=True)
      lock.Release()

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

        subject = 'Package is lacking a file: %s' % p.filename
        body = (
            'The following package is lacking a DMG file: \n'
            'https://%s/admin/package/%s' % (
                settings.SERVER_HOSTNAME, p.filename))
        mail.SendMail([settings.EMAIL_ADMIN_LIST], subject, body)

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
          if not b.filename and not b.size:
            b.delete()
            break
          subject = 'Orphaned Blob in Blobstore: %s' % b.filename
          body = (
              'An orphaned Blob exists in Blobstore. Use App Engine Admin '
              'Console\'s "Blob Viewer" to locate and delete this Blob.\n\n'
              'Filename: %s\nBlobstore Key: %s' % (b.filename, key))
          mail.SendMail([settings.EMAIL_ADMIN_LIST], subject, body)
          break
        time.sleep(1)
