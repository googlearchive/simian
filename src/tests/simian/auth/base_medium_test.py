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
#
#

"""base module tests."""




import datetime
import os
import struct

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.auth import base
import base_test


def GetRandomInt():
  """Returns a random 128-bit unsigned integer."""
  b = os.urandom(16)
  a = struct.unpack('QQ', b)
  return (a[0] << 64) + a[1]


class Auth1Test(base_test.AuthTestingBase):
  """Test Auth1 class."""

  def GetTestClass(self):
    return base.Auth1()

  def testStep1(self):
    """Test the first step of Auth1 authentication."""
    self.mox.StubOutWithMock(self.ba, 'Nonce')
    self.mox.StubOutWithMock(self.ba, '_AssembleMessage')
    self.mox.StubOutWithMock(self.ba, 'Sign')
    self.mox.StubOutWithMock(self.ba, 'SessionSetCnSn')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64encode')

    sn = GetRandomInt()
    cn = GetRandomInt()

    self.ba.Nonce().AndReturn(sn)
    m = '%s %s' % (cn, sn)
    self.ba._AssembleMessage(str(cn), str(sn)).AndReturn(m)
    self.ba.Sign(m).AndReturn('SIGN(%s)' % m)
    base.base64.urlsafe_b64encode('SIGN(%s)' % m).AndReturn('B64SIG')
    self.ba._AssembleMessage(m, 'B64SIG').AndReturn('%s B64SIG' % m)
    self.ba.SessionSetCnSn(cn, sn)

    self.mox.ReplayAll()
    self.AssertState(base.State.INPUT)
    self.AssertAuthState(base.AuthState.UNKNOWN)

    self.ba.Input(n=str(cn))
    self.AssertState(base.State.OUTPUT)
    self.assertEqual(self.ba.Output(), self._MakeMsg(cn, sn, 'B64SIG'))
    self.AssertState(base.State.INPUT)
    # despite the output of a signed data, we are NOT authenticated yet
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.mox.VerifyAll()

  def testStep2Success(self):
    """Test the second step of Auth1 authentication."""
    auth_token = 'X_auth_token'
    m = 'data that was signed'
    s = 'signature'
    s_b64 = 'signature, b64d'
    c = 'cert'
    c_b64 = 'cert, b64d'
    cn = '123'
    sn = '456'
    uuid = 'a-b-c-d-e-uuid'

    mock_cert = self.mox.CreateMockAnything()
    mock_cert.GetPublicKey().AndReturn(mock_cert)
    mock_cert.SetRequiredIssuer(self.ba._required_issuer).AndReturn(None)
    mock_cert.CheckAll().AndReturn(None)
    mock_cert.GetSubject().AndReturn(uuid)

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'SessionVerifyKnownCnSn')
    self.mox.StubOutWithMock(self.ba, 'SessionCreateAuthToken')
    self.mox.StubOutWithMock(self.ba, 'SessionDelCn')

    self.ba._SplitMessage(m, 3).AndReturn([c_b64, cn, sn])
    base.base64.urlsafe_b64decode(str(s_b64)).AndReturn(s)
    base.base64.urlsafe_b64decode(str(c_b64)).AndReturn(c)
    self.ba.LoadOtherCert(c).AndReturn(mock_cert)
    self.ba.VerifyDataSignedWithCert(m, s, mock_cert).AndReturn(True)
    self.ba.VerifyCertSignedByCA(mock_cert).AndReturn(True)
    self.ba.SessionVerifyKnownCnSn(cn, sn).AndReturn(True)
    self.ba.SessionCreateAuthToken(uuid).AndReturn(auth_token)
    self.ba.SessionDelCn(cn).AndReturn(True)

    self.mox.ReplayAll()
    self.AssertState(base.State.INPUT)
    self.AssertAuthState(base.AuthState.UNKNOWN)

    self.ba.Input(m=m, s=s_b64)
    self.AssertState(base.State.OUTPUT)
    self.assertEqual(self.ba.Output(), auth_token)
    self.AssertAuthState(base.AuthState.OK)
    self.AssertState(base.State.INPUT)
    self.mox.VerifyAll()

  def testStep2SplitMessageFailure(self):
    """Test the second step of Auth1 authentication.

    In this test, _SplitMessage() failed and raises MessageError,
    failing auth immediately.
    """
    m = 'data that was signed'
    s_b64 = 'signature, b64d'

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, 'AuthFail')

    self.ba._SplitMessage(m, 3).AndRaise(base.MessageError)
    self.ba.AuthFail().AndReturn(None)

    self.mox.ReplayAll()
    self.AssertState(base.State.INPUT)
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.ba.Input(m=m, s=s_b64)
    # because we mocked out AuthFail() the state here will be strange.
    self.AssertAuthState(base.AuthState.UNKNOWN)  # normally FAIL
    self.AssertState(base.State.INPUT)
    self.mox.VerifyAll()


class Auth1ClientTest(base_test.AuthTestingBase):
  """Test Auth1Client class."""

  def GetTestClass(self):
    return base.Auth1Client()

  def testStep0(self):
    """Test Step0 of the client auth."""
    self.mox.StubOutWithMock(self.ba, 'Nonce')
    self.mox.StubOutWithMock(self.ba._session, 'Set')
    self.ba.Nonce().AndReturn(1)
    self.ba._session.Set('cn', '1').AndReturn(None)

    self.mox.ReplayAll()
    self.AssertState(self.ba.DefaultState())
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.ba.Input()
    self.AssertState(base.State.OUTPUT)
    self.assertEqual('1', self.ba.Output())
    self.AssertState(self.ba.DefaultState())
    self.mox.VerifyAll()

  def testStep1(self):
    """Test Step1 of client auth."""
    cn = '111'
    sn = '555'
    s_b64 = 'signature b64'
    s = 'signature'
    m = '%s %s %s' % (cn, sn, s)
    self.ba._ca_cert = 'ca cert'
    self.ba._cert_str = 'client cert raw string'
    self.ba._session.Set('cn', cn)
    self.ba._server_cert_pem = '---- server pem ----'
    c_b64 = 'client_cert raw string in b64'
    msg = ':'.join((c_b64, cn, sn))
    cn_sn_m = '%s %s' % (cn, sn)

    mock_server_cert = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.ba, '_SplitMessage')
    self.mox.StubOutWithMock(self.ba, '_AssembleMessage')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64decode')
    self.mox.StubOutWithMock(base.base64, 'urlsafe_b64encode')
    self.mox.StubOutWithMock(self.ba, 'LoadOtherCert')
    self.mox.StubOutWithMock(self.ba, 'VerifyCertSignedByCA')
    self.mox.StubOutWithMock(self.ba, 'VerifyDataSignedWithCert')
    self.mox.StubOutWithMock(self.ba, 'Sign')
    self.mox.StubOutWithMock(self.ba._session, 'Get')

    self.ba._SplitMessage(m, 3).AndReturn((cn, sn, s_b64))
    base.base64.urlsafe_b64decode(s_b64).AndReturn(s)
    self.ba.LoadOtherCert(self.ba._server_cert_pem).AndReturn(mock_server_cert)
    self.ba.VerifyCertSignedByCA(mock_server_cert).AndReturn(True)
    self.ba._session.Get('cn').AndReturn(cn)
    self.ba._AssembleMessage(cn, sn).AndReturn(cn_sn_m)
    self.ba.VerifyDataSignedWithCert(
        cn_sn_m, s, mock_server_cert).AndReturn(True)

    base.base64.urlsafe_b64encode(self.ba._cert_str).AndReturn(c_b64)
    self.ba._AssembleMessage(c_b64, cn, sn).AndReturn(msg)
    self.ba.Sign(msg).AndReturn(s)
    base.base64.urlsafe_b64encode(s).AndReturn(s_b64)
    expect_output = {'m': msg, 's': s_b64}

    self.mox.ReplayAll()
    self.AssertState(self.ba.DefaultState())
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.ba.Input(m=m)
    self.AssertState(base.State.OUTPUT)
    self.assertEqual(expect_output, self.ba.Output())
    self.AssertState(self.ba.DefaultState())
    self.mox.VerifyAll()

  def testStep3(self):
    """Test Step3 of client auth."""
    token = base.Auth1.TOKEN

    self.mox.StubOutWithMock(self.ba._session, 'DeleteById')
    self.ba._session.DeleteById('cn')

    self.mox.ReplayAll()
    self.AssertState(self.ba.DefaultState())
    self.AssertAuthState(base.AuthState.UNKNOWN)
    self.ba.Input(t=token)
    self.AssertAuthState(base.AuthState.OK)
    self.AssertState(self.ba.DefaultState())
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
