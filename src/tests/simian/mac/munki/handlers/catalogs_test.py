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
"""Munki catalogs module tests."""

import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import catalogs


class CatalogsHandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return catalogs.Catalogs()

  def GetTestClassModule(self):
    return catalogs

  def testGetSuccess(self):
    """Tests Catalogs.get()."""
    name = 'goodname'
    self.MockDoAnyAuth()
    catalog = self.MockModelStatic(
        'Catalog', 'MemcacheWrappedGet', name, 'plist_xml')
    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(catalog).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(name)
    self.mox.VerifyAll()

  def testGet404(self):
    """Tests Catalogs.get() where name is not found."""
    name = 'badname'
    self.MockDoAnyAuth()
    self.MockModelStaticBase(
        'Catalog', 'MemcacheWrappedGet', name, 'plist_xml').AndReturn(None)
    self.response.set_status(404).AndReturn(None)

    self.mox.ReplayAll()
    self.c.get(name)
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
