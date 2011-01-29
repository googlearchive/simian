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

"""x509 module medium tests."""



import base64
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.auth import x509


def _b64(data):
  return base64.b64encode(data)

class X509CertificateTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.x = x509.X509Certificate()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testX509WithSelfSignedCertificate(self):
    """Use a self-generated cert and load it.

    The cert was generated as follows:
       openssl genrsa 1024 > host.key
       openssl req -new -x509 -subj /CN=TestCert1 -nodes -sha1 \
         -days 365 -key host.key -set_serial 12345 > host.cert
    """
    s = """
-----BEGIN CERTIFICATE-----
MIICDTCCAXagAwIBAgICMDkwDQYJKoZIhvcNAQEFBQAwFDESMBAGA1UEAxMJVGVz
dENlcnQxMB4XDTEwMDkwMzE5NTk1M1oXDTExMDkwMzE5NTk1M1owFDESMBAGA1UE
AxMJVGVzdENlcnQxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdYH6nyJ/4
bXDHswb6hhRqdNCbBHzQOoL0Da+sIyoOiJAorx6Kz5SQJmbgwWxLtQmwIkhdswN/
amCWOxH4t/kDz+oBWbTvVE+zZ0+VImQ/IAcZ9CE2m3ZcZKwDLXhO0j4REnniWJ2e
Gcjk4Ai8j4VPRMVYuJl0zswlYdR8EvI7awIDAQABo24wbDAdBgNVHQ4EFgQUvS28
XhCKPzRz79stErTkeCGDIDkwPQYDVR0jBDYwNIAUvS28XhCKPzRz79stErTkeCGD
IDmhGKQWMBQxEjAQBgNVBAMTCVRlc3RDZXJ0MYICMDkwDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQUFAAOBgQB6WcKXJicJi1JdbEib9VIUlfZpA4DPz9LpKJwzluQz
aLz7W82F6LuYkdua8KWSSpOsBUSEadJWF6zQchX+w8p5Bz5fncnJfbUA0gOPfQHn
R2VS2jugc+lwvZby3pnlFDIl7pN8R+JIRP722bej00Mswo1Mz2A979zQORxdVk44
KA==
-----END CERTIFICATE-----
"""
    x = x509.LoadCertificateFromPEM(s)
    x.CheckAll()
    self.assertEqual(12345, x.GetSerialNumber())
    self.assertEqual('CN=TestCert1', x.GetIssuer())
    self.assertEqual('CN=TestCert1', x.GetSubject())
    # note: the default when creating a x509 cert with openssl(1) is True
    self.assertTrue(x.GetMayActAsCA())
    self.assertEqual(x.GetKeyUsage(), None)
    self.assertEqual(
        _b64(x.GetFieldsData()),
        ('MIIBdqADAgECAgIwOTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwlUZXN0'
         'Q2VydDEwHhcNMTAwOTAzMTk1OTUzWhcNMTEwOTAzMTk1OTUzWjAUMRIwEAYD'
         'VQQDEwlUZXN0Q2VydDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN1g'
         'fqfIn/htcMezBvqGFGp00JsEfNA6gvQNr6wjKg6IkCivHorPlJAmZuDBbEu1'
         'CbAiSF2zA39qYJY7Efi3+QPP6gFZtO9UT7NnT5UiZD8gBxn0ITabdlxkrAMt'
         'eE7SPhESeeJYnZ4ZyOTgCLyPhU9ExVi4mXTOzCVh1HwS8jtrAgMBAAGjbjBs'
         'MB0GA1UdDgQWBBS9LbxeEIo/NHPv2y0StOR4IYMgOTA9BgNVHSMENjA0gBS9'
         'LbxeEIo/NHPv2y0StOR4IYMgOaEYpBYwFDESMBAGA1UEAxMJVGVzdENlcnQx'
         'ggIwOTAMBgNVHRMEBTADAQH/')
         )
    self.assertEqual(
        _b64(x.GetSignatureData()),
        ('elnClyYnCYtSXWxIm/VSFJX2aQOAz8/S6SicM5bkM2i8+1vNhei7mJHbmvCl'
         'kkqTrAVEhGnSVhes0HIV/sPKeQc+X53JyX21ANIDj30B50dlUto7oHPpcL2W'
         '8t6Z5RQyJe6TfEfiSET+9tm3o9NDLMKNTM9gPe/c0DkcXVZOOCg=')
        )


  def testLoadCertificateFromPEMWhenGarbageInput(self):
    """Test LoadCertificateFromPEM() with garbage input."""
    s = """
-----BEGIN CERTIFICATE-----
Ip55hC+YApgbvG1rPLrXg/c6pOWj/4d6cCqRTERQMn9xWOOBCarKrEC4qH7rxFPFY7AEic9MtC7K
5puW21xHM6Fj63wcOWSfcweMu4UbZtTrfX/hHHeJBnFRgImEK2QQtW/zgh3NNw/so3nFfX81M6YV
s41MfHUiCQ/S9PNiW1/6LP7roh38TLndhVRMqlPXJWBIKHNeQz9zBL/zvJ6/sZNK6QVMkSnR/UNf
6fSalfRcVLL4w+m+9YYftnVhXyEqX3WnuFp/xXPAOlAoxf2/cKS6J+w8Qwb/GQyJ4HcvIux3sa7P
pGEktBi83nPOUQEheCesLz6Hr3LC5Q/8yKZA99knkzm6FVpE7vUyPJH/ut9PDJl5gGcx994eRm7A
sa/McuPYAFM4UPSQU9JDcfa+1XshNG+9/+7z3YvTWReXztN+wttAXuSaVzuQaokxlU5I3heCdmyr
8UIqh4OcqyugZ9o8KIIlotkqRlfEQ7tZ5amROsZILAexA4M7x859oPNzEvaO5hrWwDYTKVHITWVF
K7MNpEFFXK+1vQkcxcOqCZ9JaTMA6Y+/LKbonHFDXkm+JVuzJN6f3XrWf5sSJ8U63p5rzVTyivNH
Ka3nKDUU4XUIIIb0m5FTz230P8xkvpw/8r6IhyLDf6Iy1JWA6u7zqgVGCQ6jHWUuf+cMEly0gtO4
GmgJluZ9VCw9m1sxlEARmA==
-----END CERTIFICATE-----
"""
    self.assertRaises(
        x509.CertificateASN1FormatError,
        x509.LoadCertificateFromPEM,
        s)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()