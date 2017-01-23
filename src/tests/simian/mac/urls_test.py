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
"""urls module tests."""

import logging

import re
import types

import tests.appenginesdk
import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac import urls


class SimianMainModuleTest(mox.MoxTestBase):
  """Test module level portions of urls."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testStructure(self):
    """Test the overall structure of the module."""
    self.assertTrue(hasattr(urls, 'app'))
    self.assertEqual(
        urls.webapp2.WSGIApplication, type(urls.app))

  def testWgsiAppInitArgs(self):
    """Test the arguments that are supplied to setup the app var."""

    def wsgiapp_hook(*args, **kwargs):
      o = self.mox.CreateMockAnything()
      o.set_by_test_hook = 1
      o.args = args
      o.kwargs = kwargs
      return o

    self.stubs.Set(
        urls.webapp2, 'WSGIApplication', wsgiapp_hook)
    self.mox.ReplayAll()
    reload(urls)
    app = urls.app
    self.assertNotEqual(
        urls.webapp2.WSGIApplication, type(app))
    self.assertTrue(hasattr(app, 'set_by_test_hook'))
    self.assertTrue(type(app.args) is types.TupleType)
    self.assertTrue(type(app.args[0]) is types.ListType)
    self.assertTrue(type(app.kwargs) is types.DictType)

    for (regex, cls) in app.args[0]:
      _ = re.compile(regex)
      self.assertTrue(issubclass(cls, urls.webapp2.RequestHandler))

    if 'debug' in app.kwargs:
      self.assertTrue(type(app.kwargs['debug']) is types.BooleanType)

    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
