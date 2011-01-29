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
from google.appengine.ext import blobstore
from google.appengine.ext import db


def SafeBlobDel(blobstore_key):
  """Helper method to delete a blob by its key.

  Args:
    blobstore_key: str, a blob key
  """
  try:
    blobstore.delete(blobstore_key)
  except blobstore.Error, e:
    logging.info((
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
    logging.info((
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