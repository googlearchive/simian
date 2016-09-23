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
"""gae_util module tests."""

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.common import gae_util


class GaeUtilModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testSafeBlobDel(self):
    """Test SafeBlobDel()."""
    self.mox.StubOutWithMock(gae_util.blobstore, 'delete_async')
    self.mox.StubOutWithMock(gae_util.logging, 'info')
    blobstore_key = 'key'
    gae_util.blobstore.delete_async(blobstore_key).AndReturn(None)
    gae_util.blobstore.delete_async(blobstore_key).AndRaise(
        gae_util.blobstore.Error)
    exc = ''
    gae_util.logging.warning((
        'blobstore.delete(%s) failed: %s. '
        'this key is now probably orphaned.'), blobstore_key, str(exc))
    self.mox.ReplayAll()
    gae_util.SafeBlobDel(blobstore_key)
    gae_util.SafeBlobDel(blobstore_key)
    self.mox.VerifyAll()

  def testSafeEntityDel(self):
    """Test SafeEntityDel()."""
    key_name = 'fookeyname'
    self.mox.StubOutWithMock(gae_util.logging, 'info')
    entity = self.mox.CreateMockAnything()
    entity.delete_async().AndRaise(gae_util.db.Error)
    key = self.mox.CreateMockAnything()
    entity.key().AndReturn(key)
    key.name().AndReturn(key_name)
    exc = ''
    gae_util.logging.warning((
        'Model.delete(%s) failed: %s. '
        'this entity is now probably empty.'),  key_name, str(exc))
    self.mox.ReplayAll()
    gae_util.SafeEntityDel(entity)
    self.mox.VerifyAll()

  def testGetBlobAndDel(self):
    """Test GetBlobAndDel()."""
    blobstore_key = 'key123'
    blob_str = '10 print "hi"  20 goto 10'
    mock_br = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(
        gae_util, 'blobstore', self.mox.CreateMock(gae_util.blobstore))
    self.mox.StubOutWithMock(gae_util, 'SafeBlobDel')

    gae_util.blobstore.BlobReader(blobstore_key).AndReturn(mock_br)
    mock_br.read(1024 * 1024).AndReturn(blob_str)
    mock_br.close()
    gae_util.SafeBlobDel(blobstore_key).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(blob_str, gae_util.GetBlobAndDel(blobstore_key))
    self.mox.VerifyAll()


class QueryIteratorTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testIteration(self):
    """."""
    mock_query = self.mox.CreateMockAnything()
    step = 2

    first_iteration = [1, 2]
    second_iteration = [3, 4]

    entities = first_iteration + second_iteration

    mock_query.fetch(step).AndReturn(first_iteration)
    mock_query.cursor().AndReturn('cursor1')
    mock_query.with_cursor('cursor1')
    mock_query.fetch(step).AndReturn(second_iteration)
    mock_query.cursor().AndReturn('cursor2')
    mock_query.with_cursor('cursor2')
    mock_query.fetch(step).AndReturn([])

    self.mox.ReplayAll()
    out = []
    for entity in gae_util.QueryIterator(mock_query, step=step):
      out.append(entity)
    self.assertEqual(out, entities)
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
