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

"""Shared resources for App Engine."""




import logging
import time
from google.appengine.api import memcache
from google.appengine.ext import blobstore
from google.appengine.ext import db


def BatchDatastoreOp(op, entities_or_keys, batch_size=25):
  """Performs a batch Datastore operation on a sequence of keys or entities.

  Args:
    op: func, Datastore operation to perform, i.e. db.put or db.delete.
    entities_or_keys: sequence, db.Key or db.Model instances.
    batch_size: int, number of keys or entities to batch per operation.
  """
  for i in xrange(0, len(entities_or_keys), batch_size):
    op(entities_or_keys[i:i + batch_size])


def SafeBlobDel(blobstore_key):
  """Helper method to delete a blob by its key.

  Args:
    blobstore_key: str, a blob key
  """
  try:
    blobstore.delete(blobstore_key)
  except blobstore.Error, e:
    logging.warning((
      'blobstore.delete(%s) failed: %s. '
      'this key is now probably orphaned.'), blobstore_key, str(e))


def SafeEntityDel(entity):
  """Helper method to delete an entity.

  Args:
    entity: App Engine db.Model instance.
  """
  try:
    entity.delete()
  except db.Error, e:
    logging.warning((
      'Model.delete(%s) failed: %s. '
      'this entity is now probably empty.'), entity.key().name(), str(e))


def GetBlobAndDel(blobstore_key):
  """Get a blob, delete it and return what was its contents.

  Note: Only for use with SMALL Blobs (under 1024x1024 bytes).

  Args:
    blobstore_key: str, a blob key
  Returns:
    str, the blob data
  """
  blob_reader = blobstore.BlobReader(blobstore_key)
  blob_str = blob_reader.read(1024 * 1024)  #  bigger than any pkginfo
  blob_reader.close()
  SafeBlobDel(blobstore_key)
  return blob_str



class QueryIterator(object):
  """Class to assist with iterating over big App Engine Datastore queries.

  NOTE: this class is not compatible with queries using filters with IN or !=.
  """

  def __init__(self, query, step=1000):
    self._query = query
    self._step = step

  def __iter__(self):
    """Iterate over query results safely avoiding 30s query limitations."""
    while True:
      entities = self._query.fetch(self._step)
      if not entities:
        raise StopIteration
      for entity in entities:
        yield entity
      self._query.with_cursor(self._query.cursor())


def ObtainLock(name, timeout=0):
  """Obtain a lock, given a name.

  Args:
    name: str, name of lock
    timeout: int, if >0, wait timeout seconds for a lock if it cannot
      be obtained at first attempt.  NOTE:  Using a timeout near or greater
      than the AppEngine deadline will be hazardous to your health.
      The deadline is 30s for live http, 10m for offline tasks as of
      this note.
  Returns:
    True if lock was obtained
    False if lock was not obtained, some other process has the lock
  """
  memcache_key = 'lock_%s' % name
  while 1:
    locked = memcache.incr(memcache_key, initial_value=0) == 1
    timeout -= 1
    if locked or timeout < 0:
      return locked
    time.sleep(1)
  return False


def ReleaseLock(name):
  """Release a lock, given its name.

  Args:
    name: str, name of lock
  """
  memcache_key = 'lock_%s' % name
  memcache.delete(memcache_key)