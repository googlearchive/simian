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
"""Module to help with updating InstallLog schema with new applesus property.

This file is completely unneeded if you're starting with a clean and empty
InstallLog model in Datastore.

Previously, models.InstallLog was designed to only hold Munki pkg installs. With
the introduction of Apple SUS integration, Apple SUS and Munki installs were
both stored in InstallLog, but there wasn't a way to tell them apart so an
'applesus' boolean property was added to InstallLog.

Furthermore, Simian started keeping track of whether an install was successful
or not in a single "success" boolean, rather than having to check that status
was equal or not equal to 0.

This module contains two functions that help with the switch from the InstallLog
without the applesus or success properties to the newer InstallLog with the
properties.

  UpdateInstallLogSchema:
    call put() on all entities so the applesus and success properties aren't
    missing, so reports that filter('applesus', bool) or filter('success', bool)
    don't omit such entities.

This module contains other maintenance functions to assist with schema upgrades
or rebuilding various caches.
"""

import logging

from google.appengine.ext import deferred

from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.cron import reports_cache


INSTALL_LOG_MAX_FETCH = 2000


def RebuildInstallCounts():
  """Rebuilds "install_counts" dictionary from all InstallLog entities."""
  lock = models.KeyValueCache.get_by_key_name('pkgs_list_cron_lock')
  if lock:
    lock.delete()
  cursor_obj = models.KeyValueCache.get_by_key_name('pkgs_list_cursor')
  if cursor_obj:
    cursor_obj.delete()
  models.ReportsCache.SetInstallCounts({})
  deferred.defer(reports_cache._GenerateInstallCounts)


def UpdateInstallLogSchema(cursor=None, num_updated=0):
  """Puts all InstallLog entities so any new properties are created."""
  q = models.InstallLog.all()

  if cursor:
    logging.debug('Continuing with cursor: %s', cursor)
    q.with_cursor(cursor)

  entities = q.fetch(INSTALL_LOG_MAX_FETCH)
  if not entities:
    logging.debug('No remaining entities to convert.')
    return

  entities_to_put = []
  for e in entities:
    e.success = e.IsSuccess()
    e.applesus = getattr(e, 'applesus', False)
    if not getattr(e, 'server_datetime', False):
      e.server_datetime = e.mtime
    entities_to_put.append(e)
  gae_util.BatchDatastoreOp(models.db.put, entities_to_put, 100)

  cursor = q.cursor()
  num_updated += len(entities_to_put)
  logging.info('%s entities converted', num_updated)

  deferred.defer(UpdateInstallLogSchema, cursor=cursor, num_updated=num_updated)
