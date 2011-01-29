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

"""models module tests."""




import re
import types
import tests.appenginesdk
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac import models


class ModelsModuleTest(mox.MoxTestBase):
  """Test module level portions of models."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testBaseModelMemcacheWrappedGet(self):
    """Test the BaseModel.MemcacheWrappedGet method for particular property."""
    key_name = 'foo_key_name'
    mock_entity = self.mox.CreateMockAnything()
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)
    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(
        models.BaseModel, 'get_by_key_name', self.mox.CreateMockAnything())
    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)
    models.memcache.set(memcache_key_name, mock_entity, 300).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(
      mock_entity, models.BaseModel.MemcacheWrappedGet(key_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWithPropName(self):
    """Test the BaseModel.MemcacheWrappedGet method for particular property."""
    value = 'good value'
    prop_name = 'blah_value'
    key_name = 'foo_key_name'
    mock_entity = self.mox.CreateMockAnything()
    setattr(mock_entity, prop_name, value)
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)
    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(
        models.BaseModel, 'get_by_key_name', self.mox.CreateMockAnything())
    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)
    models.memcache.set(memcache_key_name, mock_entity, 300).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(
      value, models.BaseModel.MemcacheWrappedGet(key_name, prop_name))
    self.mox.VerifyAll()

  def testMemcacheWrappedGetAllFilter(self):
    """Test the BaseModel.MemcacheWrappedGetAllFilter method."""
    filters = (('foo =', 'bar'), ('one =', 1))
    filter_str = '_foo =,bar_|_one =,1_'
    memcache_key_name = 'mwgaf_%s%s' % (models.BaseModel.kind(), filter_str)
    entities = ['the','entities']

    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(models.BaseModel, 'all')
    mock_query = self.mox.CreateMockAnything()

    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.all().AndReturn(mock_query)
    for filt, value in filters:
      mock_query.filter(filt, value).AndReturn(mock_query)
    mock_query.fetch(1000).AndReturn(entities)
    models.memcache.set(memcache_key_name, entities, 300).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
      entities, models.BaseModel.MemcacheWrappedGetAllFilter(filters))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()