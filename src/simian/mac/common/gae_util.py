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
"""Shared resources for App Engine."""

import logging

from google.appengine.ext import blobstore
from google.appengine.ext import db

from simian.mac.common import datastore_locks


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
    blobstore.delete_async(blobstore_key)
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
    entity.delete_async()
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


def LockExists(name):
  """Returns True if a lock with the given str name exists, False otherwise."""
  e = datastore_locks._DatastoreLockEntity.get_by_id(name)  # pylint: disable=protected-access
  if e:
    return e.lock_held
  return False
