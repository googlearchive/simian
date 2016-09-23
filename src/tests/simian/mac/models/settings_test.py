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


from google.apputils import app
from google.apputils import basetest
from simian.mac.models import settings


class SettingsTest(basetest.TestCase):
  """Test Settings class."""

  def testGetSettingsType(self):
    """Test GetSettingsType()."""
    self.assertEqual(settings.Settings.GetType('ca_public_cert_pem'), 'pem')
    self.assertEqual(
        settings.Settings.GetType('foo_ca_public_cert_pem'), 'pem')
    self.assertEqual(settings.Settings.GetType('unknown'), None)
    self.assertEqual(settings.Settings.GetType('email_reply_to'), 'string')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
