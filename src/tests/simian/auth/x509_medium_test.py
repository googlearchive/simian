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