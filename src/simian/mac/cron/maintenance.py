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
import re
import time
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.munki import common
from simian.mac.munki import plist


class AuthSessionCleanup(webapp.RequestHandler):
  """Class to invoke auth session cleanup routines when called."""

  def get(self):
    """Handle GET"""
    asd = gaeserver.AuthSessionSimianServer()
    expired_sessions_count = asd.ExpireAll()
    #logging.debug(
    #    'AuthSessionCleanup: %d sessions expired.', expired_sessions_count)


class MarkComputersInactive(webapp.RequestHandler):
  """Class to mark all inactive hosts as such in Datastore."""

  def get(self):
    """Handle GET."""
    #logging.debug('Marking inactive computers....')
    count = models.Computer.MarkInactive()
    #logging.debug('Complete! Marked %s inactive.' % count)


class UpdateAverageInstallDurations(webapp.RequestHandler):
  """Class to update average install duration pkginfo descriptions reguarly."""

  AVG_DURATION_TEXT = (
      '%d users have installed this with an average duration of %d seconds.')
  AVG_DURATION_REGEX = re.compile(
      '\d+ users have installed this with an average duration of \d+ seconds\.')

  def _GetUpdatedDescription(self, duration_dict, desc):
    """."""
    avg_duration_text = self.AVG_DURATION_TEXT % (
        duration_dict['duration_count'], duration_dict['duration_seconds_avg'])
    # Add new or replace existing avg duration message with updated one.
    if self.AVG_DURATION_REGEX.search(desc):
      desc = self.AVG_DURATION_REGEX.sub(avg_duration_text, desc)
    else:
      if desc:
        desc = '%s\n\n%s' % (desc, avg_duration_text)
      else:
        desc = avg_duration_text
    return desc

  def _ParsePackageInfoPlist(self, plist_xml):
    """Parses a plist and returns a MunkiPackageInfoPlist object.

    Args:
      plist_xml: str plist xml.
    Returns:
      MunkiPackageInfoPlist object, or None if there were parsing errors.
    """
    try:
      pl = plist.MunkiPackageInfoPlist(plist_xml)
      pl.Parse()
      return pl
    except plist.Error, e:
      logging.exception('Error parsing pkginfo: %s', str(e))
      return None

  def get(self):
    """Handle GET."""
    pkgs, unused_dt = models.ReportsCache.GetInstallCounts()

    for p in models.PackageInfo.all():
      pl = self._ParsePackageInfoPlist(p.plist)
      if not pl:
        continue  # skip over plist parsing errors.

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
      old_description = pl.get('description', '')
      new_description = self._GetUpdatedDescription(
          pkgs[p.munki_name], old_description)
      if old_description != new_description:
        pl['description'] = new_description
        p.plist = pl.GetXml()
        p.put()
      gae_util.ReleaseLock(lock)

    # Asyncronously regenerate all Catalogs to include updated pkginfo plists.
    delay = 0
    for c in models.Catalog.all():
      delay += 5
      common.CreateCatalog(c.name, delay=delay)


class VerifyPackages(webapp.RequestHandler):
  """Class to verify all packages have matching Blobstore blobs."""

  def get(self):
    """Handle GET."""
    #logging.debug('Verifying all PackageInfo and Blobstore Blobs....')
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
    #logging.debug(
    #    'Verification of %d PackageInfo entities and %d Blobs complete.',
    #    pkginfo_count, blob_count)