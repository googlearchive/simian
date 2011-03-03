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

"""Common classes for Macsimian unit tests.

Contents:

  RequestHandlerTest
"""



import tests.appenginesdk
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac import models
from simian.mac.common import auth
from simian import settings


class GenericContainer(object):
  """Generic data container for testing purposes.

  This class can have attributes set on it (and retrieved to full effect),
  and can have any function called on it (they will do nothing).
  """

  class GenericFunction(object):
    """Emulates a function and does nothing."""

    def __call__(self, *args):
      pass

  def __init__(self, **kwargs):
    """Take all kwargs and set them as retrievable attributes."""
    for key in kwargs:
      setattr(self, key, kwargs[key])


class TestBase(mox.MoxTestBase):
  """Base class."""


class RequestHandlerTest(TestBase):
  """Test class for RequestHandler derived classes."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.GenericRequestTestSetup()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def GetTestClassInstance(self):
    """Return the test class instance."""
    raise NotImplemented('Must implement GetTestClassInstance')

  def GetTestClassModule(self):
    """Return the module the test class is located in."""
    raise NotImplemented('Must implement GetTestClassModule')

  def GetTestClassInstanceVariableName(self):
    """Return the name of the test class instance variable.

    Returns:
      str like 'classundertest'
    """
    return 'c'

  def GenericRequestTestSetup(self):
    """Setup a standard mocked webapp.Request test framework."""
    self._test = self.GetTestClassInstance()
    setattr(self, self.GetTestClassInstanceVariableName(), self._test)
    self.request = self.mox.CreateMockAnything()
    self.request.headers = self.mox.CreateMockAnything()
    self.request.headers.get = self.mox.CreateMockAnything()
    self.response = self.mox.CreateMockAnything()
    self.response.headers = self.mox.CreateMockAnything()
    self.send_blob = self.mox.CreateMockAnything()
    self._test.request = self.request
    self._test.response = self.response
    self._test.response.out = self.response
    self._test.send_blob = self.send_blob
    self._set_mock = {}

  def MockSelf(self, name):
    """Mock a method in the tested class's instance."""
    if not name in self._set_mock:
      self.mox.StubOutWithMock(self._test, name)
      self._set_mock[name] = 1

  def MockError(self, status_code):
    """Mock an error().

    Args:
      status_code: int, like 400
    """
    self.MockSelf('error')
    self._test.error(status_code).AndReturn(None)

  def MockSetStatus(self, status_code, message=None):
    """Mock a response.set_status().

    Args:
      status_code: int, like 400
      message: str, optional, like "Bad request"
    """
    if message is None:
      self._test.response.set_status(status_code).AndReturn(None)
    else:
      self._test.response.set_status(status_code, message).AndReturn(None)

  def MockRedirect(self, url):
    """Mock a .redirect().

    Args:
      url: str, like '/foo'
    """
    self.MockSelf('redirect')
    self._test.redirect(url).AndReturn(None)

  def MockDoUserAuth(self, user=None, fail=False):
    """Mock calling auth.DoUserAuth().

    Args:
      user: user for DoUserAuth to return.
      fail: bool, whether to fail or not
    """
    if not 'authDoUserAuth' in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoUserAuth')
      self._set_mock['authDoUserAuth'] = 1
    if fail:
      auth.DoUserAuth().AndRaise(auth.NotAuthenticated)
    else:
      auth.DoUserAuth().AndReturn(user)

  def MockDoMunkiAuth(self, fail=False, and_return=None, **kwargs):
    """Mock calling gaeserver.DoMunkiAuth().

    Args:
      fail: bool, whether to fail or not; calls AndRaise()
      and_return: any, variable to pass to AndReturn, default None
      kwargs: other options, like require_level=int
    """
    munki_auth_module = self.GetTestClassModule().gaeserver
    if not hasattr(munki_auth_module, 'DoMunkiAuth'):
      raise NotImplemented('MockDoMunkiAuth for non-Munki handler class')
    if not 'authDoMunkiAuth' in self._set_mock:
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
    if not 'authDoAnyAuth' in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoAnyAuth')
      self._set_mock['authDoAnyAuth'] = 1
    if fail:
      auth.DoAnyAuth().AndRaise(auth.NotAuthenticated)
    else:
      auth.DoAnyAuth().AndReturn(and_return)

  def MockDoAdminMachineAuth(self, fail=False, and_return=None, **kwargs):
    """Mock calling auth.AdminMachineAuth().

    Args:
      fail: bool, whether to fail or not
      and_return: any, variable to pass to AndReturn, default None
    """
    if not 'authDoAdminMachineAuth' in self._set_mock:
      self.mox.StubOutWithMock(auth, 'DoAdminMachineAuth')
      self._set_mock['authDoAdminMachineAuth'] = 1
    if fail:
      auth.DoAdminMachineAuth(**kwargs).AndRaise(auth.NotAuthenticated)
    else:
      auth.DoAdminMachineAuth(**kwargs).AndReturn(and_return)

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
    if not '%s:%s' % (model_name, method_name) in self._set_mock:
      mock_model = self.mox.CreateMock(getattr(model_class, method_name))
      self.stubs.Set(model_class, method_name, mock_model)
      self._set_mock['%s:%s' % (model_name, method_name)] = mock_model
    model = self.mox.CreateMockAnything()
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
      args: list, optional arguments supplied to model instantiation
      kwargs: dict, optional arguments supplied to model instantiation
    Returns:
      a new mocked instance of the model
    """
    test_class_models = self.GetTestClassModule().models

    if not 'models_%s' % model_name in self._set_mock:
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


# Provide sane settings values
settings.ADMINS = ['admin@example.com']


def main(unused_argv):
  basetest.main()