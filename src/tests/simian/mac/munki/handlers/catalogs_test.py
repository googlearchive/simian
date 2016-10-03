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

import httplib
import logging


import mock
import stubout
import webtest

from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest

from simian.mac import models
from simian.mac.munki.handlers import catalogs
from simian.mac.urls import app as gae_app


@mock.patch.object(catalogs.auth, 'DoAnyAuth')
class CatalogsHandlersTest(basetest.TestCase):

  def setUp(self):
    super(CatalogsHandlersTest, self).setUp()
    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='user@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()
    self.testapp = webtest.TestApp(gae_app)

  def tearDown(self):
    super(CatalogsHandlersTest, self).tearDown()
    self.testbed.deactivate()

  def testGetSuccess(self, _):
    """Tests Catalogs.get()."""
    name = 'goodname'

    catalog_xml = '<plist><dict></dict></plist>'
    models.Catalog(key_name=name, _plist=catalog_xml).put()

    resp = self.testapp.get('/catalogs/' + name, status=httplib.OK)
    self.assertTrue(resp.body.find('plist') != -1)

  def testGet404(self, _):
    """Tests Catalogs.get() where name is not found."""
    name = 'badname'

    self.testapp.get('/catalogs/' + name, status=httplib.NOT_FOUND)


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
