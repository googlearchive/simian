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
"""settings module tests."""

import datetime
import os
import types


import tests.appenginesdk
from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest

# pylint: disable=g-import-not-at-top
# Set an environment variable so the settings module knows when it's being
# tested directly, versus used for testing other modules.
os.environ['____TESTING_SETTINGS_MODULE'] = 'yes'
from simian import settings
del os.environ['____TESTING_SETTINGS_MODULE']

from simian.mac import models
# pylint: enable=g-import-not-at-top


class DatastoreSettingsTest(basetest.TestCase):
  """Test DatastoreSettings."""

  def setUp(self):
    super(DatastoreSettingsTest, self).setUp()

    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='zerocool@example.com',
        USER_ID='123',
        USER_IS_ADMIN='1',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()

    if self.__class__.__name__ == 'BaseSettingsTestBase':
      return

    module_name = settings.DatastoreSettings.__name__
    self.module = types.ModuleType(module_name)

    # Derive a class from this class that plugs in the test _Globals()
    # function. This makes testing more predictable as the contents
    # of the settings module may change at any time.
    class DerivedSettingsClass(settings.DatastoreSettings):

      def _Globals(xself):  # pylint: disable=no-self-argument
        """Returns globals dict like globals()."""
        return {'FOO': 1}
    self.settings = DerivedSettingsClass(self.module)

  def tearDown(self):
    super(DatastoreSettingsTest, self).tearDown()
    self.testbed.deactivate()

  def testGetWhenDict(self):
    """Test _PopulateGlobals()."""
    self.assertEqual(self.settings.foo, 1)

  def testGetFromDatastore(self):
    value = 42
    models.Settings.SetItem('k', value)

    self.assertEquals(value, self.settings.k)

  def testSet(self):
    value = '423'
    self.settings.long_name = value

    v, stamp = models.Settings.GetItem('long_name')
    self.assertEquals(value, v)
    self.assertGreater(
        datetime.timedelta(seconds=1), datetime.datetime.utcnow() - stamp)

  def testDir(self):
    models.Settings.SetItem('some_extra_long_kEy', 343423)

    keys = dir(self.settings)

    self.assertIn('FOO', keys)
    self.assertIn('SOME_EXTRA_LONG_KEY', keys)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
