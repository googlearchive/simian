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
"""client module tests."""

import logging
logging.basicConfig(filename='/dev/null')


import mock
import stubout

from google.apputils import app
from google.apputils import basetest

from tests.simian import test_settings
from simian.auth import client


class AuthSessionSimianClientTest(basetest.TestCase):
  """Test AuthSessionSimianClient class."""

  def testBasic(self):
    self.assertTrue(issubclass(
        client.AuthSessionSimianClient, client.base.Auth1ClientSession))


class AuthSimianClientTest(basetest.TestCase):
  """Test AuthSimianClient class."""

  def setUp(self):
    self.apc = client.AuthSimianClient()

  def testGetSessionClass(self):
    self.assertTrue(
        self.apc.GetSessionClass() is client.AuthSessionSimianClient)

  def testLoadCaParameters(self):
    """Test _LoadCaParameters()."""
    self.apc.LoadCaParameters(test_settings)
    self.assertEqual(self.apc._ca_pem, test_settings.CA_PUBLIC_CERT_PEM)
    self.assertEqual(
        self.apc._server_cert_pem, test_settings.SERVER_PUBLIC_CERT_PEM)
    self.assertEqual(
        self.apc._required_issuer, test_settings.REQUIRED_ISSUER)

  @mock.patch.object(client.util, 'GetCaParameters')
  def testLoadCaParametersWhenError(self, m):
    """Test _LoadCaParameters()."""
    m.side_effect = client.util.CaParametersError
    self.assertRaises(
        client.CaParametersError, self.apc.LoadCaParameters, test_settings)

    m.assert_called_once_with(test_settings, omit_server_private_key=True)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
