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

  def testBaseModelMemcacheAddAutoUpdateTask(self):
    """Test BaseModel.MemcacheAddAutoUpdateTask()."""

    class _BaseModel(models.BaseModel):
      pass

    # nothing set yet
    self.assertFalse(hasattr(_BaseModel, '_memcache_auto_update_tasks'))

    # attempt to use a task that doesn't exist
    self.assertRaises(
        ValueError,
        _BaseModel.MemcacheAddAutoUpdateTask,
        'func', 1, foo='bar')
    self.assertFalse(hasattr(_BaseModel, '_memcache_auto_update_tasks'))

    # attempt to use non-executable attribute as task
    _BaseModel.NotAFunction = 1
    self.assertRaises(
        ValueError,
        _BaseModel.MemcacheAddAutoUpdateTask,
        'NotAFunction', 1, foo='bar')
    self.assertFalse(hasattr(_BaseModel, '_memcache_auto_update_tasks'))

    # successful
    _BaseModel.MemcacheAddAutoUpdateTask('ResetMemcacheWrap', 1, foo='bar')
    self.assertEqual(
        _BaseModel._memcache_auto_update_tasks,
        [('ResetMemcacheWrap', (1,), {'foo': 'bar'})])

  def testBaseModelMemcacheAutoUpdate(self):
    """Test BaseModel.MemcacheAutoUpdate()."""

    class _BaseModel(models.BaseModel):
      pass
    _BaseModel.MemcacheAddAutoUpdateTask(
        'MemcacheWrappedDelete', 1, 2, 3, foo='bar')

    b = _BaseModel()
    self.mox.StubOutWithMock(_BaseModel, 'MemcacheWrappedDelete', True)
    _BaseModel.MemcacheWrappedDelete(1, 2, 3, foo='bar').AndReturn(None)
    self.mox.ReplayAll()
    b.MemcacheAutoUpdate(_deferred=True)
    self.mox.VerifyAll()

  def testBaseModelMemcacheAutoUpdateWhenNoTasks(self):
    """Test BaseModel.MemcacheAutoUpdate() when no tasks."""
    class _BaseModel(models.BaseModel):
      pass

    b = _BaseModel()
    self.mox.ReplayAll()
    b.MemcacheAutoUpdate()
    self.mox.VerifyAll()

  def testBaseModelMemcacheAutoUpdateWhenNotDeferred(self):
    """Test BaseModel.MemcacheAutoUpdate() when _deferred not supplied."""
    class _BaseModel(models.BaseModel):
      pass
    _BaseModel._memcache_auto_update_tasks = 'exists'

    b = _BaseModel()
    self.mox.StubOutWithMock(models.deferred, 'defer')
    models.deferred.defer(
        b.MemcacheAutoUpdate, _deferred=True, _countdown=10).AndReturn(None)
    self.mox.ReplayAll()
    b.MemcacheAutoUpdate()
    self.mox.VerifyAll()

  def testPut(self):
    """Test put()."""
    class _BaseModel(models.BaseModel):
      pass

    mock_func = self.mox.CreateMockAnything()

    b = _BaseModel()
    
    if type(__builtins__) is dict:
      # __builtins__ is a dict under setuptools + python. ???
      self.mox.StubOutWithMock(models.db.Model, 'put')
      models.db.Model.put('arg').AndReturn(None)
    else:
      self.mox.StubOutWithMock(__builtins__, 'super')
      __builtins__.super(models.BaseModel, b).AndReturn(mock_func)
      mock_func.put('arg').AndReturn(None)
    self.mox.StubOutWithMock(b, 'MemcacheAutoUpdate')
    b.MemcacheAutoUpdate().AndReturn(None)

    self.mox.ReplayAll()
    b.put('arg')
    self.mox.VerifyAll()

  def testBaseModelResetMemcacheWrap(self):
    """Test BaseModel.ResetMemcacheWrap()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'kind')
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name')

    memcache_key = 'mwg_kind_key'
    models.BaseModel.kind().AndReturn('kind')
    models.BaseModel.get_by_key_name('key').AndReturn('entity')
    models.memcache.set(memcache_key, 'entity', 300).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.ResetMemcacheWrap('key')
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGet(self):
    """Test BaseModel.MemcacheWrappedGet()."""
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

  def testBaseModelMemcacheWrappedGetNoEntity(self):
    """Test BaseModel.MemcacheWrappedGet() when entity does not exist."""
    key_name = 'foo_key_name'
    mock_entity = self.mox.CreateMockAnything()
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)
    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(
        models.BaseModel, 'get_by_key_name', self.mox.CreateMockAnything())
    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(
      None, models.BaseModel.MemcacheWrappedGet(key_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWithPropName(self):
    """Test BaseModel.MemcacheWrappedGet() for particular property."""
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

  def testMemcacheWrappedSet(self):
    """Test BaseModel.MemcacheWrappedSet()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'kind')
    self.mox.StubOutWithMock(models.BaseModel, 'get_or_insert')

    entity = self.mox.CreateMockAnything()
    memcache_key = 'mwg_kind_key'
    models.BaseModel.kind().AndReturn('kind')
    models.BaseModel.get_or_insert('key').AndReturn(entity)
    entity.put()
    models.memcache.set(
        memcache_key, entity, 300).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.MemcacheWrappedSet('key', 'prop', 'value')
    self.mox.VerifyAll()

  def testMemcacheWrappedDeleteWhenKeyName(self):
    """Test BaseModel.MemcacheWrappedDelete() when key_name supplied."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'kind')
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name')

    entity = self.mox.CreateMockAnything()
    memcache_key = 'mwg_kind_key'
    models.BaseModel.get_by_key_name('key').AndReturn(entity)
    entity.delete().AndReturn(None)
    models.BaseModel.kind().AndReturn('kind')
    models.memcache.delete(memcache_key).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.MemcacheWrappedDelete(key_name='key')
    self.mox.VerifyAll()

  def testMemcacheWrappedDeleteWhenEntity(self):
    """Test BaseModel.MemcacheWrappedDelete() when entity supplied."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'kind')
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name')

    entity = self.mox.CreateMockAnything()
    entity.key().AndReturn(entity)
    entity.name().AndReturn('key')
    memcache_key = 'mwg_kind_key'
    entity.delete().AndReturn(None)
    models.BaseModel.kind().AndReturn('kind')
    models.memcache.delete(memcache_key).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.MemcacheWrappedDelete(entity=entity)
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetAllFilter(self):
    """Test BaseModel.MemcacheWrappedGetAllFilter()."""
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

  def testBaseModelMemcacheWrappedPropMapGenerate(self):
    """Test BaseModel.MemcacheWrappedPropMapGenerate()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'all')
    self.mox.StubOutWithMock(models.gae_util, 'ObtainLock')
    self.mox.StubOutWithMock(models.gae_util, 'ReleaseLock')
    mock_query = self.mox.CreateMockAnything()
    mock_iterator = self.mox.CreateMockAnything()

    key_name = 'key'
    prop_name = 'prop'
    entities = [
      self.mox.CreateMockAnything(),
      self.mox.CreateMockAnything(),
    ]

    for p in xrange(0, 2):
      setattr(entities[p], prop_name, 'value%d' % p)
      entities[p].key().AndReturn('key%d' % p)

    map_data = {'value0': ['key0'], 'value1': ['key1']}

    lock_name = 'mwpm_BaseModel_%s' % prop_name
    models.gae_util.ObtainLock(lock_name).AndReturn(True)

    models.BaseModel.all().AndReturn(mock_query)
    mock_query.__iter__().AndReturn(mock_iterator)
    p = 0
    for e in entities:
      mock_iterator.next().AndReturn(entities[p])
      p += 1
    mock_iterator.next().AndRaise(StopIteration)

    memcache_key = 'mwpm_BaseModel_%s' % prop_name
    models.memcache.set(memcache_key, map_data, 300).AndReturn(None)

    models.gae_util.ReleaseLock(lock_name).AndReturn(True)

    self.mox.ReplayAll()
    models.BaseModel.MemcacheWrappedPropMapGenerate(prop_name)
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGenerateLocked(self):
    """Test BaseModel.MemcacheWrappedPropMapGenerate()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.gae_util, 'ObtainLock')
    prop_name = 'prop'

    lock_name = 'mwpm_BaseModel_%s' % prop_name
    models.gae_util.ObtainLock(lock_name).AndReturn(False)

    self.mox.ReplayAll()
    self.assertEqual(
        None, models.BaseModel.MemcacheWrappedPropMapGenerate(prop_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGenerateLockedDefer(self):
    """Test BaseModel.MemcacheWrappedPropMapGenerate()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.deferred, 'defer')
    self.mox.StubOutWithMock(models.gae_util, 'ObtainLock')
    prop_name = 'prop'

    lock_name = 'mwpm_BaseModel_%s' % prop_name
    models.gae_util.ObtainLock(lock_name).AndReturn(False)
    models.deferred.defer(
        models.BaseModel.MemcacheWrappedPropMapGenerate,
        prop_name,
        defer_if_locked=True,
        memcache_secs=300,
        _countdown=10).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        None, models.BaseModel.MemcacheWrappedPropMapGenerate(
            prop_name, defer_if_locked=True))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGetAll(self):
    """Test MemcacheWrappedPropMapGetAll()."""
    prop_name = 'prop'
    value = 'value'
    memcache_key = 'mwpm_BaseModel_%s' % prop_name
    map_data = {value: ['key0']}
    entities = 'entities'

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.deferred, 'defer')
    self.mox.StubOutWithMock(models.BaseModel, 'get')

    models.memcache.get(memcache_key).AndReturn(map_data)
    models.BaseModel.get(map_data[value]).AndReturn(entities)

    self.mox.ReplayAll()
    self.assertEqual(
        entities, models.BaseModel.MemcacheWrappedPropMapGetAll(
            prop_name, value))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGetAllWhenNoValue(self):
    """Test MemcacheWrappedPropMapGetAll()."""
    prop_name = 'prop'
    value = 'value'
    memcache_key = 'mwpm_BaseModel_%s' % prop_name
    map_data = {'%s_not' % value: ['key0']}
    entities = 'entities'

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.deferred, 'defer')
    self.mox.StubOutWithMock(models.BaseModel, 'get')

    models.memcache.get(memcache_key).AndReturn(map_data)

    self.mox.ReplayAll()
    self.assertRaises(
        KeyError, models.BaseModel.MemcacheWrappedPropMapGetAll,
        prop_name, value)
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGetAllWhenEmptyMapInMemcache(self):
    """Test MemcacheWrappedPropMapGetAll()."""
    prop_name = 'prop'
    value = 'value'
    memcache_key = 'mwpm_BaseModel_%s' % prop_name
    entities = 'entities'

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.deferred, 'defer')
    self.mox.StubOutWithMock(models.BaseModel, 'get')

    models.memcache.get(memcache_key).AndReturn({})

    self.mox.ReplayAll()
    self.assertRaises(
        KeyError, models.BaseModel.MemcacheWrappedPropMapGetAll,
        prop_name, value)
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedPropMapGetAllWhenNoMapInMemcache(self):
    """Test MemcacheWrappedPropMapGetAll()."""
    prop_name = 'prop'
    value = 'value'
    memcache_key = 'mwpm_BaseModel_%s' % prop_name
    map_data = {value: ['key0']}
    entities = 'entities'

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.deferred, 'defer')
    self.mox.StubOutWithMock(models.BaseModel, 'get')

    models.memcache.get(memcache_key).AndReturn(None)
    models.deferred.defer(
        models.BaseModel.MemcacheWrappedPropMapGenerate,
        prop_name).AndReturn(None)
    models.BaseModel.MemcacheWrappedGetAllFilter(
        (('%s =' % prop_name, value),)).AndReturn(entities)

    self.mox.ReplayAll()
    self.assertEqual(
        entities, models.BaseModel.MemcacheWrappedPropMapGetAll(
            prop_name, value))
    self.mox.VerifyAll()

  def testPackageAliasResolvePackageName(self):
    """Test PackageAlias.ResolvePackageName() classmethod."""
    pkg_alias = 'unknown'
    pkg_name = 'foopkg'
    mock_entity = self.mox.CreateMockAnything()
    mock_entity.enabled = True
    mock_entity.munki_pkg_name = pkg_name
    self.mox.StubOutWithMock(models.PackageAlias, 'MemcacheWrappedGet')
    models.PackageAlias.MemcacheWrappedGet(pkg_alias).AndReturn(mock_entity)
    self.mox.ReplayAll()
    self.assertEqual(
        pkg_name, models.PackageAlias.ResolvePackageName(pkg_alias))
    self.mox.VerifyAll()

  def testPackageAliasResolvePackageNameDisabled(self):
    """Test PackageAlias.ResolvePackageName() classmethod."""
    pkg_alias = 'unknown'
    pkg_name = 'foopkg'
    mock_entity = self.mox.CreateMockAnything()
    mock_entity.enabled = False
    mock_entity.munki_pkg_name = pkg_name
    self.mox.StubOutWithMock(models.PackageAlias, 'MemcacheWrappedGet')
    models.PackageAlias.MemcacheWrappedGet(pkg_alias).AndReturn(mock_entity)
    self.mox.ReplayAll()
    self.assertEqual(
        None, models.PackageAlias.ResolvePackageName(pkg_alias))
    self.mox.VerifyAll()

  def testPackageAliasResolvePackageNameEmptyPkgName(self):
    """Test PackageAlias.ResolvePackageName() classmethod."""
    pkg_alias = 'unknown'
    pkg_name = ''
    mock_entity = self.mox.CreateMockAnything()
    mock_entity.enabled = True
    mock_entity.munki_pkg_name = pkg_name
    self.mox.StubOutWithMock(models.PackageAlias, 'MemcacheWrappedGet')
    models.PackageAlias.MemcacheWrappedGet(pkg_alias).AndReturn(mock_entity)
    self.mox.ReplayAll()
    self.assertEqual(
        None, models.PackageAlias.ResolvePackageName(pkg_alias))
    self.mox.VerifyAll()

  def testPackageAliasResolvePackageName_AliasNotFound(self):
    """Test PackageAlias.ResolvePackageName() classmethod."""
    pkg_alias = 'unknown'
    self.mox.StubOutWithMock(models.PackageAlias, 'MemcacheWrappedGet')
    models.PackageAlias.MemcacheWrappedGet(pkg_alias).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(None, models.PackageAlias.ResolvePackageName(pkg_alias))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()