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
"""models module tests."""

import tests.appenginesdk

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.models import base as models


class ModelsModuleTest(mox.MoxTestBase):
  """Test module level portions of models."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testPut(self):
    """Test put()."""

    class _BaseModel(models.BaseModel):
      pass

    mock_func = self.mox.CreateMockAnything()

    b = _BaseModel()

    if type(__builtins__) is dict:
      # __builtins__ is a dict under setuptools + python. ???
      self.mox.StubOutWithMock(models.db.Model, 'put')
      models.db.Model.put().AndReturn(None)
    else:
      self.mox.StubOutWithMock(__builtins__, 'super')
      __builtins__.super(models.BaseModel, b).AndReturn(mock_func)
      mock_func.put().AndReturn(None)

    self.mox.ReplayAll()
    b.put()
    self.mox.VerifyAll()

  def testBaseModelDeleteMemcacheWrap(self):
    """Test BaseModel.DeleteMemcacheWrap()."""
    self.mox.StubOutWithMock(models, 'memcache', True)

    memcache_key = 'mwg_BaseModel_key'
    models.memcache.delete(memcache_key).AndReturn(None)

    prop_name = 'foo_name'
    memcache_key_with_prop_name = 'mwgpn_BaseModel_key_%s' % prop_name
    models.memcache.delete(memcache_key_with_prop_name).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.DeleteMemcacheWrap('key')
    models.BaseModel.DeleteMemcacheWrap('key', prop_name=prop_name)
    self.mox.VerifyAll()

  def testBaseModelResetMemcacheWrap(self):
    """Test BaseModel.ResetMemcacheWrap()."""
    self.mox.StubOutWithMock(models.BaseModel, 'DeleteMemcacheWrap', True)
    self.mox.StubOutWithMock(models.BaseModel, 'MemcacheWrappedGet', True)

    key_name = 'mwg_BaseModel_key'
    prop_name = 'foo_name'

    models.BaseModel.DeleteMemcacheWrap(
        key_name, prop_name=prop_name).AndReturn(None)
    models.BaseModel.MemcacheWrappedGet(
        key_name, prop_name=prop_name, memcache_secs=10).AndReturn(None)

    self.mox.ReplayAll()
    models.BaseModel.ResetMemcacheWrap(
        key_name, prop_name=prop_name, memcache_secs=10)
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGet(self):
    """Test BaseModel.MemcacheWrappedGet() when not cached."""
    key_name = 'foo_key_name'
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_to_protobuf', True)
    mock_entity = self.mox.CreateMockAnything()

    models.db.model_to_protobuf(mock_entity).AndReturn(mock_entity)  # cheat
    mock_entity.SerializeToString().AndReturn('serialized')
    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)
    models.memcache.set(
        memcache_key_name, 'serialized', models.MEMCACHE_SECS).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        mock_entity, models.BaseModel.MemcacheWrappedGet(key_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWhenMemcacheSetFail(self):
    """Test BaseModel.MemcacheWrappedGet() when not cached."""
    key_name = 'foo_key_name'
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_to_protobuf', True)
    mock_entity = self.mox.CreateMockAnything()

    models.db.model_to_protobuf(mock_entity).AndReturn(mock_entity)  # cheat
    mock_entity.SerializeToString().AndReturn('serialized')
    models.memcache.get(memcache_key_name).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)
    models.memcache.set(
        memcache_key_name, 'serialized',
        models.MEMCACHE_SECS).AndRaise(ValueError)

    self.mox.ReplayAll()
    self.assertEqual(
        mock_entity, models.BaseModel.MemcacheWrappedGet(key_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWhenCached(self):
    """Test BaseModel.MemcacheWrappedGet() when cached."""
    key_name = 'foo_key_name'
    memcache_key_name = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_from_protobuf', True)
    mock_entity = self.mox.CreateMockAnything()

    models.memcache.get(memcache_key_name).AndReturn('serialized')
    models.db.model_from_protobuf('serialized').AndReturn(mock_entity)

    self.mox.ReplayAll()
    self.assertEqual(
        mock_entity, models.BaseModel.MemcacheWrappedGet(key_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWhenCachedBadSerialization(self):
    """Test BaseModel.MemcacheWrappedGet() when cached."""
    key_name = 'foo_key_name'
    memcache_key = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_from_protobuf', True)

    class ProtocolBufferDecodeError(Exception):
      pass

    models.memcache.get(memcache_key).AndReturn('serialized')
    models.db.model_from_protobuf('serialized').AndRaise(
        ProtocolBufferDecodeError)
    models.memcache.delete(memcache_key).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        None, models.BaseModel.MemcacheWrappedGet(key_name, retry=True))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWhenCachedBadSerializationUnexpected(self):
    """Test BaseModel.MemcacheWrappedGet() when cached."""
    key_name = 'foo_key_name'
    memcache_key = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_from_protobuf', True)

    models.memcache.get(memcache_key).AndReturn('serialized')
    models.db.model_from_protobuf('serialized').AndRaise(Exception)
    models.memcache.delete(memcache_key).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        None, models.BaseModel.MemcacheWrappedGet(key_name, retry=True))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWhenCachedPropName(self):
    """Test BaseModel.MemcacheWrappedGet() when cached."""
    key_name = 'foo_key_name'
    prop_name = 'prop'
    memcache_key = 'mwgpn_%s_%s_%s' % (
        models.BaseModel.kind(), key_name, prop_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_from_protobuf', True)

    models.memcache.get(memcache_key).AndReturn('value')

    self.mox.ReplayAll()
    self.assertEqual(
        'value', models.BaseModel.MemcacheWrappedGet(key_name, prop_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetNoEntity(self):
    """Test BaseModel.MemcacheWrappedGet() when entity does not exist."""
    key_name = 'foo_key_name'
    memcache_key = 'mwg_%s_%s' % (models.BaseModel.kind(), key_name)

    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(
        models.BaseModel, 'get_by_key_name', self.mox.CreateMockAnything())

    models.memcache.get(memcache_key).AndReturn(None)
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
    memcache_key = 'mwgpn_%s_%s_%s' % (
        models.BaseModel.kind(), key_name, prop_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    self.mox.StubOutWithMock(models.db, 'model_to_protobuf', True)
    mock_entity = self.mox.CreateMockAnything()

    setattr(mock_entity, prop_name, value)

    models.memcache.get(memcache_key).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)
    models.memcache.set(
        memcache_key, value, models.MEMCACHE_SECS).AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual(
        value, models.BaseModel.MemcacheWrappedGet(key_name, prop_name))
    self.mox.VerifyAll()

  def testBaseModelMemcacheWrappedGetWithNonExistentPropName(self):
    """Test BaseModel.MemcacheWrappedGet() for non-existent property."""
    prop_name = 'bad_prop'
    key_name = 'foo_key_name'
    memcache_key = 'mwgpn_%s_%s_%s' % (
        models.BaseModel.kind(), key_name, prop_name)

    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'get_by_key_name', True)
    mock_entity = object()

    self.assertFalse(hasattr(mock_entity, prop_name))
    models.memcache.get(memcache_key).AndReturn(None)
    models.BaseModel.get_by_key_name(key_name).AndReturn(mock_entity)

    self.mox.ReplayAll()
    self.assertEqual(
        None, models.BaseModel.MemcacheWrappedGet(key_name, prop_name))
    self.mox.VerifyAll()

  def testMemcacheWrappedSet(self):
    """Test BaseModel.MemcacheWrappedSet()."""
    self.mox.StubOutWithMock(models, 'memcache', True)
    self.mox.StubOutWithMock(models.BaseModel, 'kind')
    self.mox.StubOutWithMock(models.BaseModel, 'get_or_insert')
    self.mox.StubOutWithMock(models.db, 'model_to_protobuf', True)
    mock_entity = self.mox.CreateMockAnything()

    memcache_entity_key = 'mwg_kind_key'
    memcache_key = 'mwgpn_kind_key_prop'
    models.BaseModel.kind().AndReturn('kind')
    models.BaseModel.kind().AndReturn('kind')
    models.BaseModel.get_or_insert('key').AndReturn(mock_entity)
    mock_entity.put()
    models.db.model_to_protobuf(mock_entity).AndReturn(mock_entity)  # cheat
    mock_entity.SerializeToString().AndReturn('serialized')
    models.memcache.set(
        memcache_key, 'value', models.MEMCACHE_SECS).AndReturn(None)
    models.memcache.set(
        memcache_entity_key, 'serialized',
        models.MEMCACHE_SECS).AndReturn(None)

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
    memcache_key = 'mwgaf_%s%s' % (models.BaseModel.kind(), filter_str)
    entities = ['the', 'entities']

    self.mox.StubOutWithMock(models, 'memcache', self.mox.CreateMockAnything())
    self.mox.StubOutWithMock(models.BaseModel, 'all')
    mock_query = self.mox.CreateMockAnything()

    models.memcache.get(memcache_key).AndReturn(None)
    models.BaseModel.all().AndReturn(mock_query)
    for filt, value in filters:
      mock_query.filter(filt, value).AndReturn(mock_query)
    mock_query.fetch(1000).AndReturn(entities)
    models.memcache.set(
        memcache_key, entities, models.MEMCACHE_SECS).AndReturn(None)

    self.mox.ReplayAll()
    self.assertEqual(
        entities, models.BaseModel.MemcacheWrappedGetAllFilter(filters))
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


class BaseManifestModificationTest(mox.MoxTestBase):
  """BaseManifestModification class test."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGenerateInstance(self):
    """TODO(user): Should be completed."""

  def testResetModMemcache(self):
    """Test ResetModMemcache()."""
    target = 'target'
    mod_type_invalid = 'UNKNOWN'
    mod_type = models.MANIFEST_MOD_MODELS.keys()[0]
    mod_type_cls = models.MANIFEST_MOD_MODELS[mod_type]

    self.mox.StubOutWithMock(mod_type_cls, 'DeleteMemcacheWrappedGetAllFilter')
    mod_type_cls.DeleteMemcacheWrappedGetAllFilter(
        (('%s =' % mod_type, target),)).AndReturn(None)

    self.mox.ReplayAll()
    self.assertTrue(mod_type_invalid not in models.MANIFEST_MOD_MODELS)
    self.assertRaises(
        ValueError, models.BaseManifestModification.ResetModMemcache,
        mod_type_invalid, target)

    models.BaseManifestModification.ResetModMemcache(mod_type, target)
    self.mox.VerifyAll()


class KeyValueCacheTest(mox.MoxTestBase):
  """Test KeyValueCache class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.cls = models.KeyValueCache
    self.key = 'example_ip_blocks'

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testIpInListWhenEmptyIp(self):
    """Tests IpInList() with empty IP values."""
    self.assertEqual(False, self.cls.IpInList(self.key, ''))
    self.assertEqual(False, self.cls.IpInList(self.key, None))

  def testIpInListWhenIpNotInEmptyList(self):
    """Tests IpInList() with an IP that will not match an empty list."""
    self.mox.StubOutWithMock(models.util, 'Deserialize')
    self.mox.StubOutWithMock(self.cls, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = []

    self.cls.MemcacheWrappedGet(
        self.key, 'text_value').AndReturn('serialized')
    models.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertFalse(self.cls.IpInList(self.key, ip))
    self.mox.VerifyAll()

  def testIpInListWhenPropertyValueIsEmpty(self):
    """Tests IpInList() with null/empty property text_value for list."""
    self.mox.StubOutWithMock(models.util, 'Deserialize')
    self.mox.StubOutWithMock(self.cls, 'MemcacheWrappedGet')

    ip = '1.2.3.4'

    self.cls.MemcacheWrappedGet(self.key, 'text_value').AndReturn('')

    self.mox.ReplayAll()
    self.assertFalse(self.cls.IpInList(self.key, ip))
    self.mox.VerifyAll()

  def testIpInListWhenIpNotInList(self):
    """Tests IpInList() with an IP not in the lists."""
    self.mox.StubOutWithMock(models.util, 'Deserialize')
    self.mox.StubOutWithMock(self.cls, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = ['192.168.0.0/16']

    self.cls.MemcacheWrappedGet(
        self.key, 'text_value').AndReturn('serialized')
    models.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertFalse(self.cls.IpInList(self.key, ip))
    self.mox.VerifyAll()

  def testIpInListWhenTrue(self):
    """Tests IpInList() with an IP that is found in the list."""
    self.mox.StubOutWithMock(models.util, 'Deserialize')
    self.mox.StubOutWithMock(self.cls, 'MemcacheWrappedGet')

    ip = '1.2.3.4'
    deserialized = ['192.168.0.0/16', '1.0.0.0/8']

    self.cls.MemcacheWrappedGet(
        self.key, 'text_value').AndReturn('serialized')
    models.util.Deserialize('serialized').AndReturn(deserialized)

    self.mox.ReplayAll()
    self.assertTrue(self.cls.IpInList(self.key, ip))
    self.mox.VerifyAll()

  def testIpInListWhenIpv6(self):
    """Tests IpInList() with an IPv6 IP."""
    ip = '2620:0:1003:1007:216:36ff:feee:f090'

    self.mox.ReplayAll()
    self.assertFalse(self.cls.IpInList(self.key, ip))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
