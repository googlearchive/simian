#!/usr/bin/env python
#
# Copyright 2012 Google Inc. All Rights Reserved.
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
#

"""settings module tests."""



import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from tests.simian import test_settings
from simian.auth import util


class SettingsModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.settings = self._GetTestSettings()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GetTestSettings(self):
    """Copy test_settings into a new container and return it."""
    m = type(test_settings)('test_settings')
    for k in dir(test_settings):
      if k[0] >= 'A' and k[0] <= 'Z':
        setattr(m, k, getattr(test_settings, k))
    return m

  def testCaIdRe(self):
    """Test the CA_ID_RE regex."""
    self.assertTrue(util.CA_ID_RE.search('FOO') is not None)
    self.assertTrue(util.CA_ID_RE.search('Y2012') is not None)

    self.assertTrue(util.CA_ID_RE.search('') is None)
    self.assertTrue(util.CA_ID_RE.search('2222') is None)
    self.assertTrue(util.CA_ID_RE.search('2FOO') is None)

  def testGetCaIdWhenNone(self):
    """Test GetCaId()."""
    self.settings.CA_ID = None

    self.mox.ReplayAll()
    ca_id = util.GetCaId(self.settings)
    self.assertTrue(ca_id is None)
    self.mox.VerifyAll()

  def testGetCaIdWhenFoo(self):
    """Test GetCaId()."""
    self.settings.CA_ID = 'FOO'

    self.mox.ReplayAll()
    ca_id = util.GetCaId(self.settings)
    self.assertEqual(ca_id, 'FOO')
    self.mox.VerifyAll()

  def testGetCaParametersWithOmitServerPrivateKey(self):
    """Test GetCaParameters()."""
    self.settings.CA_ID = None

    self.mox.StubOutWithMock(util, 'GetCaId')
    util.GetCaId(self.settings).AndReturn(None)  # CA_ID=None

    self.mox.ReplayAll()
    p = util.GetCaParameters(self.settings, omit_server_private_key=True)
    self.assertEqual(p.ca_public_cert_pem, self.settings.CA_PUBLIC_CERT_PEM)
    self.assertEqual(
        p.server_public_cert_pem, self.settings.SERVER_PUBLIC_CERT_PEM)
    self.assertEqual(p.required_issuer, self.settings.REQUIRED_ISSUER)
    self.assertEqual(p.server_private_key_pem, None)
    self.assertTrue(p.ca_id is None)
    self.mox.VerifyAll()

  def testGetCaParametersWhenFollowCaIdValueNone(self):
    """Test GetCaParameters()."""
    self.settings.CA_ID = None

    self.mox.StubOutWithMock(util, 'GetCaId')
    util.GetCaId(self.settings).AndReturn(None)  # CA_ID=None

    self.mox.ReplayAll()
    p = util.GetCaParameters(self.settings)
    self.assertEqual(p.ca_public_cert_pem, self.settings.CA_PUBLIC_CERT_PEM)
    self.assertEqual(
        p.server_public_cert_pem, self.settings.SERVER_PUBLIC_CERT_PEM)
    self.assertEqual(p.server_private_key_pem,  'foo_server_private_pem')
    self.assertEqual(p.required_issuer, self.settings.REQUIRED_ISSUER)
    self.assertTrue(p.ca_id is None)
    self.mox.VerifyAll()

  def testGetCaParametersWhenForcePrimaryCaSettings(self):
    """Test GetCaParameters()."""
    # Mock to detect that it was NOT called:
    self.mox.StubOutWithMock(util, 'GetCaId')

    self.mox.ReplayAll()
    p = util.GetCaParameters(self.settings, None)  # Force primary CA settings
    self.assertEqual(p.ca_public_cert_pem, self.settings.CA_PUBLIC_CERT_PEM)
    self.assertEqual(
        p.server_public_cert_pem, self.settings.SERVER_PUBLIC_CERT_PEM)
    self.assertEqual(p.server_private_key_pem,  'foo_server_private_pem')
    self.assertEqual(p.required_issuer, self.settings.REQUIRED_ISSUER)
    self.assertTrue(p.ca_id is None)
    self.mox.VerifyAll()

  def testGetCaParametersWhenCaIdFoo(self):
    """Test GetCaParameters()."""
    ca_id = 'FOO'
    self.mox.StubOutWithMock(util, 'GetCaId')
    util.GetCaId(self.settings).AndReturn(ca_id)  # CA_ID='FOO'

    self.settings.CA_ID = ca_id
    self.settings.FOO_CA_PUBLIC_CERT_PEM = '__ca!'
    self.settings.FOO_SERVER_PUBLIC_CERT_PEM = '__pub!'
    self.settings.FOO_SERVER_PRIVATE_KEY_PEM = '__priv!'
    self.settings.FOO_REQUIRED_ISSUER = '__ri!'

    self.mox.ReplayAll()
    p = util.GetCaParameters(self.settings)
    self.assertEqual(p.ca_public_cert_pem, '__ca!')
    self.assertEqual(p.server_public_cert_pem, '__pub!')
    self.assertEqual(p.server_private_key_pem,  '__priv!')
    self.assertEqual(p.required_issuer, '__ri!')
    self.assertEqual(p.ca_id, ca_id)
    self.mox.VerifyAll()

  def testGetCaParametersWhenCaIdFooAndOptionalParam(self):
    """Test GetCaParameters()."""
    ca_id = 'FOO'
    self.mox.StubOutWithMock(util, 'GetCaId')
    util.GetCaId(self.settings).AndReturn(ca_id)  # CA_ID='FOO'

    self.settings.CA_ID = ca_id
    self.settings.FOO_CA_PUBLIC_CERT_PEM = '__ca!'
    self.settings.FOO_SERVER_PUBLIC_CERT_PEM = '__pub!'
    # intentionally omit:
    # self.settings.FOO_SERVER_PRIVATE_KEY_PEM = '__priv!'
    self.settings.FOO_REQUIRED_ISSUER = '__ri!'

    self.mox.ReplayAll()
    p = util.GetCaParameters(self.settings)
    self.assertEqual(p.ca_public_cert_pem, '__ca!')
    self.assertEqual(p.server_public_cert_pem, '__pub!')
    self.assertEqual(p.server_private_key_pem,  None)
    self.assertEqual(p.required_issuer, '__ri!')
    self.assertEqual(p.ca_id, ca_id)
    self.mox.VerifyAll()

  def testGetCaParametersWhenCaIdBarAndMissingParam(self):
    """Test GetCaParameters()."""
    ca_id = 'BAR'
    self.mox.StubOutWithMock(util, 'GetCaId')
    util.GetCaId(self.settings).AndReturn(ca_id)  # CA_ID='FOO'

    self.settings.CA_ID = ca_id
    self.settings.BAR_CA_PUBLIC_CERT_PEM = '__ca!'
    self.settings.BAR_SERVER_PUBLIC_CERT_PEM = '__pub!'
    self.settings.BAR_SERVER_PRIVATE_KEY_PEM = '__priv!'
    # intentionally omit:
    # self.settings.BAR_REQUIRED_ISSUER = '__ri!'

    self.mox.ReplayAll()
    self.assertRaises(
        util.CaParametersError, util.GetCaParameters, self.settings)
    self.mox.VerifyAll()

  def testGetCaParametersWhenInvalidCaId(self):
    """Test GetCaParameters()."""
    self.assertRaises(
        util.CaParametersError, util.GetCaParameters, self.settings, '_what')

  def testGetCaParametersDefault(self):
    """Test GetCaParametersDefault()."""
    self.mox.StubOutWithMock(util, 'GetCaParameters')
    settings = {'whatever': 1}
    util.GetCaParameters(
        settings, None, omit_server_private_key=False).AndReturn('ok')

    self.mox.ReplayAll()
    self.assertEqual('ok', util.GetCaParametersDefault(settings))
    self.mox.VerifyAll()

  def testGetCaParametersDefaultWithOmitServerPrivateKey(self):
    """Test GetCaParametersDefault()."""
    self.mox.StubOutWithMock(util, 'GetCaParameters')
    settings = {'whatever': 1}
    util.GetCaParameters(
        settings, None, omit_server_private_key=True).AndReturn('ok')

    self.mox.ReplayAll()
    self.assertEqual(
        'ok',
        util.GetCaParametersDefault(settings, omit_server_private_key=True))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
