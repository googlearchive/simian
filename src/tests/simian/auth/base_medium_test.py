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
"""base module tests."""

import array
import base64
import datetime
import os
import struct


import mock
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.auth import x509
from tests.simian import test_settings
from simian.auth import base

CLIENT_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIICzTCCAbWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJBVTET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMB4XDTE2MDUxMjIxMDEzNloXDTI2MDUxMDIxMDEzNlowFjEUMBIGA1UE
AxMLVzEyMzQ1NjdBQkMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALiVteBD
keSIAe/c5sa6ISPANpdhq8gyN44P7e7eJtiSsAM2PMTc9oj17bnFfMetHtN8hOvT
KKLGZJuPeBWP78Am9tFpNdTRpf7uy0bv60jeBcMowESDoVJ78N8amCuaRs0vEzWu
EAK6Z9+6e0BRC26p1yAg+RPV9MoFuHJiSmS3AgMBAAGjezB5MAkGA1UdEwQCMAAw
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G
A1UdDgQWBBQIBu/rtw3KplAaO1dDk2049Mz6pjAfBgNVHSMEGDAWgBQTswJFDL/O
so8V69yFKssvLkBBTzANBgkqhkiG9w0BAQUFAAOCAQEAdDBhlJ9OgQvCuPY60pBQ
P4KHZupJcIWJka8bJzh9Fj0dbksGzO418AL5PheeZk/0h3CpwGyPa1jhB0htONOW
Ye/vBby91nlXUA5VuPqrv5O6n2O2rpyitg3Njo1ivCyyVhYfe8PwsHLFB+uSHXOH
YuCF2/68R7MWQzeAmGnNluJq5hwKO4pr2QSkCj0vMZ6C0FFixwwhqaHY/9Bvt2zw
30JSW3IvjzfaLfo1fpIvocjO04wHGUmGDRUM9xQiGOVK6ovMm6+VATiwQdRhclAg
InazZdcMrcegRNAcNSoDa3q1b4K4Z4r0JsKW+3Ef9tUP31l4G+a16G2+NDI0uVcT
VA==
-----END CERTIFICATE-----
"""

CLIENT_PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALiVteBDkeSIAe/c
5sa6ISPANpdhq8gyN44P7e7eJtiSsAM2PMTc9oj17bnFfMetHtN8hOvTKKLGZJuP
eBWP78Am9tFpNdTRpf7uy0bv60jeBcMowESDoVJ78N8amCuaRs0vEzWuEAK6Z9+6
e0BRC26p1yAg+RPV9MoFuHJiSmS3AgMBAAECgYEAmBDGOE6SV4pwxhHfkWJvwMsu
bkJJyfEM8Z1P8FTV/d/C37KEF87N0AGC6mO3K60E00gnHTzlokv9QGbOkDz3Tphq
2VP8VI1iu4qtrHk7DCtBemGsyrKKBFG9J+HzKfPwFddhdZ1I/kyd/TSNqyh+kWuB
rEIlmFMSEXk1z/4Ly5ECQQDkn3kczvVnZ+QRwEPcp42JbuA8AJbXrgxd6R3B+vKe
qgXjO6LqQKvU6H3qLTXf1QhFKNi8C6RKbh5wNS7hfS6/AkEAzrA7GdNXmF8hSoAP
i8I1z+2C3FP30D0TlU5VsaVJ1DvboDAQhCgfMKiyJZnRCl2A+B5FLRKsaK2+HNR3
V8xACQJADKOAR4ZtbJ0Cr7SIS997ZJibjtWdgSjfCCYF/h5IYVsW3jwCwp52oVuE
8ngzXT9iqKgcazDdkTvLNPrLr62C8wJBAJyqoGG2/JKWqRlbcG0zTK7LDYIMc674
XLuzoOkCrK+en58QT7Sc5OdxN3eg2/7LWVK5Px4nJWBDMfOQaNW4EGECQDeDtljR
VAzTfourWBUbO7C4rQfRF4G0TsWHyjWl7PaegBKEObyIsaKDuyjwV0c0xsbZh0CH
R/rSVTJYAxkyJb4=
-----END PRIVATE KEY-----
"""


def GetRandomInt():
  """Returns a random 128-bit unsigned integer."""
  b = os.urandom(16)
  a = struct.unpack('QQ', b)
  return (a[0] << 64) + a[1]


class AuthTest(basetest.TestCase):
  """Test Auth1 class."""

  def testWalkthrough(self):
    """Test the first step of Auth1 authentication."""
    auth1 = base.Auth1()

    # Step1 Server
    cn = GetRandomInt()

    auth1.LoadSelfKey(test_settings.SERVER_PRIVATE_KEY_PEM)
    auth1._ca_pem = test_settings.CA_PUBLIC_CERT_PEM

    self.assertEqual(base.State.INPUT, auth1.State())
    self.assertEqual(base.AuthState.UNKNOWN, auth1.AuthState())

    auth1.Input(n=str(cn))
    self.assertEqual(base.State.OUTPUT, auth1.State())

    output = auth1.Output().split()

    self.assertEquals(str(cn), output[0])

    signature = array.array('B', base64.urlsafe_b64decode(output[2]))
    data = array.array('B', output[0] + ' ' + output[1])

    cert = x509.LoadCertificateFromPEM(test_settings.SERVER_PUBLIC_CERT_PEM)
    pk = cert.GetPublicKey()
    self.assertTrue(pk.hashAndVerify(signature, data))

    self.assertEqual(base.State.INPUT, auth1.State())
    # despite the output of a signed data, we are NOT authenticated yet
    self.assertEqual(base.AuthState.UNKNOWN, auth1.AuthState())

    # Step1 Client
    auth1client = base.Auth1Client()
    auth1client._session.Set('cn', str(cn))
    auth1client.LoadSelfKey(CLIENT_PRIVATE_KEY)
    auth1client.LoadSelfCert(CLIENT_CERTIFICATE)
    auth1client._server_cert_pem = test_settings.SERVER_PUBLIC_CERT_PEM
    auth1client._ca_pem = test_settings.CA_PUBLIC_CERT_PEM

    self.assertEqual(auth1client.DefaultState(), auth1client.State())
    self.assertEqual(base.AuthState.UNKNOWN, auth1client.AuthState())

    auth1client.Input(m=' '.join(output))

    self.assertEqual(base.State.OUTPUT, auth1client.State())
    output = auth1client.Output()
    self.assertTrue(output['m'])
    self.assertTrue(output['s'])
    self.assertEqual(auth1client.DefaultState(), auth1client.State())

    # Step2 Server
    self.assertEqual(base.State.INPUT, auth1.State())
    self.assertEqual(base.AuthState.UNKNOWN, auth1.AuthState())

    auth1.Input(m=output['m'], s=output['s'])

    self.assertEqual(base.State.OUTPUT, auth1.State())

    token = auth1.Output()
    self.assertTrue(token)

    self.assertEqual(base.AuthState.OK, auth1.AuthState())
    self.assertEqual(base.State.INPUT, auth1.State())

    # Step3 Client
    self.assertEqual(auth1client.DefaultState(), auth1client.State())
    self.assertEqual(base.AuthState.UNKNOWN, auth1client.AuthState())

    auth1client.Input(t=base.Auth1.TOKEN)
    self.assertEqual(base.AuthState.OK, auth1client.AuthState())
    self.assertEqual(auth1client.DefaultState(), auth1client.State())

  def testServerStep2SplitMessageFailure(self):
    """Test the second step of Auth1 authentication.

    In this test, _SplitMessage() failed and raises MessageError,
    failing auth immediately.
    """
    auth1 = base.Auth1()
    m = 'data that was signed'
    s_b64 = 'signature, b64d'

    with mock.patch.object(
        auth1, '_SplitMessage', side_effect=base.MessageError):
      self.assertEqual(base.State.INPUT, auth1.State())
      self.assertEqual(base.AuthState.UNKNOWN, auth1.AuthState())

      auth1.Input(m=m, s=s_b64)

      self.assertEqual(base.AuthState.FAIL, auth1.AuthState())
      self.assertEqual(base.State.INPUT, auth1.State())

  def testClientStep0(self):
    """Test Step0 of the client auth."""
    auth1client = base.Auth1Client()
    self.assertEqual(auth1client.DefaultState(), auth1client.State())
    self.assertEqual(base.AuthState.UNKNOWN, auth1client.AuthState())

    auth1client.Input()

    self.assertEqual(base.State.OUTPUT, auth1client.State())
    output = auth1client.Output()
    self.assertTrue(output)
    self.assertEqual(auth1client.DefaultState(), auth1client.State())


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
