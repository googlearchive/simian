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
"""Munki dynamic_manifest module tests."""

import logging
import urllib

from google.apputils import app
from simian.mac.api import dynamic_manifest as dyn_man
from tests.simian.mac.common import test


class DynamicManifestHandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return dyn_man.DynamicManifest()

  def GetTestClassModule(self):
    return dyn_man

  def _MockModTypeModel(self, mod_type):
    """Util method to help with mocking out models.MANIFEST_MOD_MODELS."""
    mock_model = self.mox.CreateMockAnything()
    dyn_man.models.MANIFEST_MOD_MODELS[mod_type] = mock_model
    return mock_model

  def testModTypes(self):
    """Tests that all valid mod_type options work."""
    mod_types = ['owner', 'os_version', 'site']
    for mod_type in mod_types:
      self.assertTrue(
          dyn_man.models.MANIFEST_MOD_MODELS.get(mod_type) is not None)
    self.assertTrue(dyn_man.models.MANIFEST_MOD_MODELS.get('crazytype') is None)

  def testParseParameters(self):
    """Tests _ParseParameters()."""
    mod_type = 'site'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'
    pkg_name_unquoted = urllib.unquote(pkg_name)

    manifests = ['unstable', 'testing']
    install_types = ['optional_installs', 'managed_updates']

    self.request.get_all('install_types').AndReturn(install_types)
    self.request.get_all('manifests').AndReturn(manifests)

    self.mox.ReplayAll()

    self.c._ParseParameters(mod_type, target, pkg_name)

    self.assertEqual(self.c.mod_type, mod_type)
    self.assertEqual(self.c.target, target)
    self.assertEqual(self.c.pkg_name, pkg_name_unquoted)
    self.assertEqual(self.c.model, dyn_man.models.MANIFEST_MOD_MODELS[mod_type])
    self.assertEqual(self.c.manifests, manifests)
    self.assertEqual(self.c.install_types, install_types)
    self.assertEqual(self.c.key_name, '%s##%s' % (target, pkg_name_unquoted))

    self.mox.VerifyAll()

  def testParseParametersOwner(self):
    """Tests _ParseParameters()."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'
    pkg_name_unquoted = urllib.unquote(pkg_name)

    install_types = ['optional_installs', 'managed_updates']

    self.request.get_all('install_types').AndReturn(install_types)

    self.mox.ReplayAll()

    self.c._ParseParameters(mod_type, target, pkg_name)

    self.assertEqual(self.c.mod_type, mod_type)
    self.assertEqual(self.c.target, target)
    self.assertEqual(self.c.pkg_name, pkg_name_unquoted)
    self.assertEqual(self.c.model, dyn_man.models.MANIFEST_MOD_MODELS[mod_type])
    self.assertEqual(self.c.manifests, [])
    self.assertEqual(self.c.install_types, install_types)
    self.assertEqual(self.c.key_name, '%s##%s' % (target, pkg_name_unquoted))

    self.mox.VerifyAll()

  def testPutMod(self):
    """Test _PutMod."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'
    install_types = ['optional_installs']

    mock_entity = self.mox.CreateMockAnything()

    # This code partially replicates self.c._ParseParameters.
    # It is hard to reuse that function for testing because it uses
    # self.request...
    self.c.mod_type = mod_type
    # Instead of dyn_man.models.MANIFEST_MOD_MODELS.get(mod_type, None)
    # plug our mock in immediately.
    self.c.model = self.mox.CreateMockAnything()
    self.c.target = urllib.unquote(target)
    self.c.pkg_name = urllib.unquote(pkg_name)
    self.c.key_name = '%s##%s' % (self.c.target, self.c.pkg_name)
    self.c.install_types = install_types
    self.c.manifests = []
    # End partially replicated section.

    self.c.model(key_name=self.c.key_name).AndReturn(mock_entity)
    self.mox.StubOutWithMock(
        dyn_man.models.BaseManifestModification, 'ResetModMemcache')

    mock_entity.put().AndReturn(True)
    dyn_man.models.BaseManifestModification.ResetModMemcache(
        mod_type, target).AndReturn(None)

    self.mox.ReplayAll()
    self.c._PutMod()
    self.mox.VerifyAll()

  def testPutModWhenError(self):
    """Test _PutMod."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'
    install_types = ['optional_installs']

    mock_entity = self.mox.CreateMockAnything()

    # This code partially replicates self.c._ParseParameters.
    # It is hard to reuse that function for testing because it uses
    # self.request...
    self.c.mod_type = mod_type
    # Instead of dyn_man.models.MANIFEST_MOD_MODELS.get(mod_type, None)
    # plug our mock in immediately.
    self.c.model = self.mox.CreateMockAnything()
    self.c.target = urllib.unquote(target)
    self.c.pkg_name = urllib.unquote(pkg_name)
    self.c.key_name = '%s##%s' % (self.c.target, self.c.pkg_name)
    self.c.install_types = install_types
    self.c.manifests = []
    # End partially replicated section.

    self.c.model(key_name=self.c.key_name).AndReturn(mock_entity)
    self.mox.StubOutWithMock(
        dyn_man.models.BaseManifestModification, 'ResetModMemcache')

    mock_entity.put().AndRaise(dyn_man.db.Error)

    self.mox.ReplayAll()
    self.assertRaises(dyn_man.db.Error, self.c._PutMod)
    self.mox.VerifyAll()

  def testGetSuccess(self):
    """Tests get()."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'
    mock_query = self._MockModTypeModel(mod_type)

    mock_entity1 = self.mox.CreateMockAnything()
    mock_entity2 = self.mox.CreateMockAnything()

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])

    self.c.model = mock_query
    self.c.model.all().AndReturn(mock_query)
    mock_query.filter('%s =' % mod_type, target).AndReturn(mock_query)
    mock_query.filter('value =', urllib.unquote(pkg_name)).AndReturn(mock_query)
    mock_iter = self.mox.CreateMockAnything()
    mock_query.__iter__().AndReturn(mock_iter)
    mock_iter.next().AndReturn(mock_entity1)
    mock_entity1.Serialize().AndReturn('1')
    mock_iter.next().AndReturn(mock_entity2)
    mock_entity2.Serialize().AndReturn('2')
    mock_iter.next().AndRaise(StopIteration)

    self.c.response.headers.__setitem__('Content-Type', 'application/json')
    self.c.response.out.write(['1', '2'])

    self.mox.ReplayAll()
    self.c.get(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testGetBadType(self):
    """Tests get() where a bad mod_type is given."""
    mod_type = 'doesntexist'
    target = 'foouser'
    pkg_name = 'Foo%20Pkg-1.2'

    self.MockDoUserAuth(is_admin=True)
    self.mox.StubOutWithMock(self.c, '_ParseParameters')
    self.c._ParseParameters(mod_type, target, pkg_name).AndRaise(
        dyn_man.InvalidModificationType)
    self.MockError(404)

    self.mox.ReplayAll()
    self.c.get(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testGetNoTarget(self):
    """Tests get() where the target is not given."""
    mod_type = 'owner'
    target = None

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])
    self.MockError(400)

    self.mox.ReplayAll()
    self.c.get(mod_type=mod_type, target=target)
    self.mox.VerifyAll()

  def testGetNoResults(self):
    """Tests get() where no results are returned."""
    mod_type = 'owner'
    target = 'foouser'
    mock_query = self._MockModTypeModel(mod_type)

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])

    self.c.model = mock_query
    self.c.model.all().AndReturn(mock_query)
    mock_query.filter('%s =' % mod_type, target).AndReturn([])
    self.MockError(404)

    self.mox.ReplayAll()
    self.c.get(mod_type=mod_type, target=target)
    self.mox.VerifyAll()

  def testPutSuccess(self):
    """Tests put() with success."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'FooPkg-1.2'
    install_types = ['optional_installs', 'managed_updates']
    key_name = '%s##%s' % (target, pkg_name)
    mock_model = self._MockModTypeModel(mod_type)
    user = 'foouser'

    self.MockDoUserAuth(is_admin=True, user=user)
    self.request.get_all('install_types').AndReturn(install_types)
    mock_model(key_name=key_name).AndReturn(mock_model)
    mock_model.put().AndReturn(None)
    self.mox.StubOutWithMock(
        dyn_man.models.BaseManifestModification, 'ResetModMemcache')
    dyn_man.models.BaseManifestModification.ResetModMemcache(
        mod_type, target).AndReturn(None)

    self.mox.ReplayAll()
    self.c.put(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.assertTrue(mock_model.enabled)
    self.assertEqual(mock_model.target, target)
    self.assertEqual(mock_model.value, pkg_name)
    self.assertEqual(mock_model.manifests, [])
    self.assertEqual(mock_model.user, user)
    self.assertEqual(mock_model.install_types, install_types)
    self.mox.VerifyAll()

  def testPutWithEmptyRequiredVar(self):
    """Tests put() with a required var that is empty."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'FooPkg-1.2'
    install_types = ['optional_installs', 'managed_updates']

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])  # no install_types!!

    self.MockError(400)

    self.mox.ReplayAll()
    self.c.put(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testDeleteSuccess(self):
    """Tests delete() with success."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'FooPkg-1.2'
    key_name = '%s##%s' % (target, pkg_name)
    mock_model = self._MockModTypeModel(mod_type)

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])

    mock_model.get_by_key_name(key_name).AndReturn(mock_model)
    mock_model.delete().AndReturn(None)

    self.mox.ReplayAll()
    self.c.delete(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testDeleteWithBadKey(self):
    """Tests delete() with success."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'FooPkg-1.2'
    key_name = '%s##%s' % (target, pkg_name)
    mock_model = self._MockModTypeModel(mod_type)

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])

    mock_model.get_by_key_name(key_name).AndReturn(None)
    self.MockError(404)

    self.mox.ReplayAll()
    self.c.delete(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testDeleteDbError(self):
    """Tests delete() with success."""
    mod_type = 'owner'
    target = 'foouser'
    pkg_name = 'FooPkg-1.2'
    key_name = '%s##%s' % (target, pkg_name)
    mock_model = self._MockModTypeModel(mod_type)

    self.MockDoUserAuth(is_admin=True)
    self.request.get_all('install_types').AndReturn([])

    mock_model.get_by_key_name(key_name).AndReturn(mock_model)
    mock_model.delete().AndRaise(dyn_man.db.Error)
    self.MockError(500)

    self.mox.ReplayAll()
    self.c.delete(mod_type=mod_type, target=target, pkg_name=pkg_name)
    self.mox.VerifyAll()

  def testPostWithPkgAlias(self):
    """Tests post() with a pkg_alias, not a pkg_name."""
    mutate = 'true'
    mod_type = 'owner'
    target = 'foouser'
    pkg_alias = 'FooPkg'
    pkg_name = 'FooPkg Premium Pro 5'
    install_types = ['optional_installs', 'managed_updates']
    key_name = '%s##%s' % (target, pkg_name)
    mock_model = self._MockModTypeModel(mod_type)
    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'

    self.MockDoOAuthAuth(user=mock_user)
    self.request.get('mod_type').AndReturn(mod_type)
    self.request.get('target').AndReturn(target)
    self.request.get('mutate', 'true').AndReturn(mutate)
    self.request.get('pkg_alias').AndReturn(pkg_alias)
    self.mox.StubOutWithMock(dyn_man.models.PackageAlias, 'ResolvePackageName')
    dyn_man.models.PackageAlias.ResolvePackageName(pkg_alias).AndReturn(
        pkg_name)

    self.request.get_all('install_types').AndReturn(install_types)


    mock_model(key_name=key_name).AndReturn(mock_model)
    mock_model.put().AndReturn(None)
    self.mox.StubOutWithMock(
        dyn_man.models.BaseManifestModification, 'ResetModMemcache')
    dyn_man.models.BaseManifestModification.ResetModMemcache(
        mod_type, target).AndReturn(None)

    self.c.response.headers.__setitem__('Content-Type', 'application/json')
    self.response.out.write(dyn_man.json.dumps([{'pkg_name': pkg_name}]))

    self.mox.ReplayAll()
    self.c.post()
    self.assertTrue(mock_model.enabled)
    self.assertEqual(mock_model.target, target)
    self.assertEqual(mock_model.value, pkg_name)
    self.assertEqual(mock_model.manifests, [])
    self.assertEqual(mock_model.user, mock_user)
    self.assertEqual(mock_model.install_types, install_types)
    self.mox.VerifyAll()

  def testPostWithPkgAliasAndWithoutMutate(self):
    """Tests post() with a pkg_alias without mutate.

    If this test is retrofitted to use a stub datastore then it should verify
    that _PutMod() was not called.
    """
    mutate = 'false'
    mod_type = 'owner'
    target = 'foouser'
    pkg_alias = 'FooPkg'
    pkg_name = 'FooPkg Premium Pro 5'
    install_types = ['optional_installs', 'managed_updates']
    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'

    self.MockDoOAuthAuth(user=mock_user)
    self.request.get('mod_type').AndReturn(mod_type)
    self.request.get('target').AndReturn(target)
    self.request.get('mutate', 'true').AndReturn(mutate)
    self.request.get('pkg_alias').AndReturn(pkg_alias)
    self.mox.StubOutWithMock(dyn_man.models.PackageAlias, 'ResolvePackageName')
    dyn_man.models.PackageAlias.ResolvePackageName(pkg_alias).AndReturn(
        pkg_name)

    self.request.get_all('install_types').AndReturn(install_types)


    self.c.response.headers.__setitem__('Content-Type', 'application/json')
    self.response.out.write(dyn_man.json.dumps([{'pkg_name': pkg_name}]))

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()




logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
