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
"""Common classes for Simian unit tests.

Contents:

  RequestHandlerTest
"""

import tests.appenginesdk

from google.appengine.ext import testbed

from google.apputils import basetest

from tests.simian.mac.common import test_base as test_base
from simian import settings
from simian.mac.common import auth


def GetArgFromCallHistory(mock_fn, call_index=0, arg_index=0):
  return mock_fn.call_args_list[call_index][0][arg_index]


class AppengineTest(basetest.TestCase):

  def setUp(self):
    super(AppengineTest, self).setUp()

    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='user@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()

  def tearDown(self):
    super(AppengineTest, self).tearDown()
    self.testbed.deactivate()


class GenericContainer(test_base.GenericContainer):
  """Generic data container for testing purposes."""


class RequestHandlerTest(test_base.RequestHandlerTest):
  """Test class for RequestHandler derived classes."""

  def setUp(self):
    super(RequestHandlerTest, self).setUp()
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='user@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_datastore_v3_stub()
    self.testbed.init_memcache_stub()
    self.testbed.init_taskqueue_stub()
    self.testbed.init_user_stub()
    self.testbed.init_mail_stub()
    settings.ADMINS = ['admin@example.com']

  def tearDown(self):
    super(RequestHandlerTest, self).tearDown()
    self.testbed.deactivate()

  def MockDoUserAuth(self, user=None, is_admin=None, fail=False):
    """Mock calling auth.DoUserAuth().

    Args:
      user: user for DoUserAuth to return.
      fail: bool, whether to fail or not
    """
    if 'authDoUserAuth' not in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoUserAuth')
      self._set_mock['authDoUserAuth'] = 1
    if fail:
      if is_admin is None:
        auth.DoUserAuth().AndRaise(auth.NotAuthenticated)
      else:
        auth.DoUserAuth(is_admin=is_admin).AndRaise(auth.NotAuthenticated)
    else:
      if is_admin is None:
        auth.DoUserAuth().AndReturn(user)
      else:
        auth.DoUserAuth(is_admin=is_admin).AndReturn(user)

  def MockDoOAuthAuth(self, user=None, is_admin=None, fail=False):
    """Mock calling auth.DoOAuthAuth().

    Args:
      user: user for DoOAuthAuth to return.
      fail: bool, whether to fail or not
    """
    if not 'authDoOAuthAuth' in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoOAuthAuth')
      self._set_mock['authDoOAuthAuth'] = 1
    if fail:
      if is_admin is None:
        auth.DoOAuthAuth().AndRaise(auth.NotAuthenticated)
      else:
        auth.DoOAuthAuth(is_admin=is_admin).AndRaise(auth.NotAuthenticated)
    else:
      if is_admin is None:
        auth.DoOAuthAuth().AndReturn(user)
      else:
        auth.DoOAuthAuth(is_admin=is_admin).AndReturn(user)

  def MockDoMunkiAuth(self, fail=False, and_return=None, **kwargs):
    """Mock calling gaeserver.DoMunkiAuth().

    Args:
      fail: bool, whether to fail or not; calls AndRaise()
      and_return: any, variable to pass to AndReturn, default None
      kwargs: other options, like require_level=int
    """
    munki_auth_module = self.GetTestClassModule().gaeserver
    if not hasattr(munki_auth_module, 'DoMunkiAuth'):
      raise NotImplementedError('MockDoMunkiAuth for non-Munki handler class')
    if 'authDoMunkiAuth' not in self._set_mock:
      self.mox.StubOutWithMock(munki_auth_module, 'DoMunkiAuth')
      self._set_mock['authDoMunkiAuth'] = 1
    if fail:
      self.GetTestClassModule().gaeserver.DoMunkiAuth(**kwargs).AndRaise(
          munki_auth_module.NotAuthenticated)
    else:
      self.GetTestClassModule().gaeserver.DoMunkiAuth(**kwargs).AndReturn(
          and_return)

  def MockDoAnyAuth(self, fail=False, and_return=None):
    """Mock calling auth.DoAnyAuth().

    Args:
      fail: bool, whether to fail or not
      and_return: any, variable to pass to AndReturn, default None
    """
    if 'authDoAnyAuth' not in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoAnyAuth')
      self._set_mock['authDoAnyAuth'] = 1
    if fail:
      auth.DoAnyAuth().AndRaise(auth.NotAuthenticated)
    else:
      auth.DoAnyAuth().AndReturn(and_return)

  def MockModelStaticBase(self, model_name, method_name, *args):
    """Mock a model static method, return a mock setup.

    Args:
      model_name: str, name of model
      method_name: str, name of static method on model to call
      *args: optional, list of arguments to supply to mock setup
    Returns:
      a mock setup ready for completion with AndReturn, AndRaise, etc.
    """
    test_class_models = self.GetTestClassModule().models
    model_class = getattr(test_class_models, model_name)
    if '%s:%s' % (model_name, method_name) not in self._set_mock:
      mock_model = self.mox.CreateMock(getattr(model_class, method_name))
      self.stubs.Set(model_class, method_name, mock_model)
      self._set_mock['%s:%s' % (model_name, method_name)] = mock_model
    return getattr(model_class, method_name)(*args)

  def MockModelStatic(self, model_name, method_name, *args):
    """Mock a model static method, return a mocked model.

    Args:
      same as MockModelStaticBase
    Returns:
      a new mocked instance of the model
    """
    model = self.mox.CreateMockAnything()
    self.MockModelStaticBase(model_name, method_name, *args).AndReturn(model)
    return model

  def MockModelStaticNone(self, model_name, method_name, *args):
    """Mock a model static method, return None.

    Used to return "no entity" type responses from static methods.
    e.g.
      MockModelStaticNone('ModelName', 'get', 12345)

    Args:
      same as MockModelStaticBase
    Returns:
      None
    """
    model = None
    self.MockModelStaticBase(model_name, method_name, *args).AndReturn(model)
    return model

  def MockModel(self, model_name, *args, **kwargs):
    """Mock creating an instance of a model, and return the mock instance.

    Args:
      name: str, name of model, like 'Package'
      *args: list, optional arguments supplied to model instantiation
      **kwargs: dict, optional arguments supplied to model instantiation
    Returns:
      a new mocked instance of the model
    """
    test_class_models = self.GetTestClassModule().models

    if 'models_%s' % model_name not in self._set_mock:
      self.mox.StubOutWithMock(
          getattr(self.GetTestClassModule(), 'models'),
          model_name)
      # we need to put back any stubs which MockModelStaticBase placed
      for mock in self._set_mock:
        if mock.startswith('%s:' % model_name):
          self.stubs.Set(
              getattr(test_class_models, model_name),
              mock.split(':')[1],
              self._set_mock[mock])
      self._set_mock['models_%s' % model_name] = 1

    model = self.mox.CreateMockAnything()
    getattr(
        self.GetTestClassModule().models,
        model_name)(*args, **kwargs).AndReturn(model)
    return model


def main(unused_argv):
  basetest.main()
