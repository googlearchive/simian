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

  def testX509WithSloppyInput(self):
    """Test LoadCertificateFromPEM with various forms of sloppy input."""

    # This cert is identical to testX509WithSelfSignedCertificate data.
    pem = """
-----BEGIN CERTIFICATE-----
MIICDTCCAXagAwIBAgICMDkwDQYJKoZIhvcNAQEFBQAwFDESMBAGA1UEAxMJVGVz
dENlcnQxMB4XDTExMDkwNjE5NTMyNVoXDTIxMDkwMzE5NTMyNVowFDESMBAGA1UE
AxMJVGVzdENlcnQxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCa7S9PpvYh
Utkw9Wu4pnV4B/kD0BaGU3irDZWhIwVEmmFkcF2GtPhSvy12Jthj1M45ME8wpyzW
svXcUMhYac12WsgFXEjqjeWhztlUZVeSUAZQW3MierrDhAR/LAeWyBGYUf6CGan6
O44OCELGJSTEg44/f1Ivj8aPYV7BuSlHawIDAQABo24wbDAdBgNVHQ4EFgQUMhwL
eP1SzD8YCkUFvX+3kC/2iYEwPQYDVR0jBDYwNIAUMhwLeP1SzD8YCkUFvX+3kC/2
iYGhGKQWMBQxEjAQBgNVBAMTCVRlc3RDZXJ0MYICMDkwDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQUFAAOBgQAsMvV0CygBEY2jkTnD/rJ4JbN+yAbpHt17FUi1k972
ww4F3igrInfF6pgk+x866HWQvrZvAXJPdMkG6V0GIaORmNaFVyAHu9bAbDTCYMri
hIYnz+CPRvK8o5NWjeGSDKZ/z5PV8j1jaKcy2S0N5pm3izDQayQdc4chRfInqkzN
Xw==
-----END CERTIFICATE-----"""

    # Missing end newline
    s = pem
    x = x509.LoadCertificateFromPEM(s)

    # Well formed input
    s = '%s\n' % pem
    x = x509.LoadCertificateFromPEM(s)

    # Extra newlines and spaces
    s = '\n  \n%s \n\n' % pem
    x = x509.LoadCertificateFromPEM(s)

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
dENlcnQxMB4XDTExMDkwNjE5NTMyNVoXDTIxMDkwMzE5NTMyNVowFDESMBAGA1UE
AxMJVGVzdENlcnQxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCa7S9PpvYh
Utkw9Wu4pnV4B/kD0BaGU3irDZWhIwVEmmFkcF2GtPhSvy12Jthj1M45ME8wpyzW
svXcUMhYac12WsgFXEjqjeWhztlUZVeSUAZQW3MierrDhAR/LAeWyBGYUf6CGan6
O44OCELGJSTEg44/f1Ivj8aPYV7BuSlHawIDAQABo24wbDAdBgNVHQ4EFgQUMhwL
eP1SzD8YCkUFvX+3kC/2iYEwPQYDVR0jBDYwNIAUMhwLeP1SzD8YCkUFvX+3kC/2
iYGhGKQWMBQxEjAQBgNVBAMTCVRlc3RDZXJ0MYICMDkwDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQUFAAOBgQAsMvV0CygBEY2jkTnD/rJ4JbN+yAbpHt17FUi1k972
ww4F3igrInfF6pgk+x866HWQvrZvAXJPdMkG6V0GIaORmNaFVyAHu9bAbDTCYMri
hIYnz+CPRvK8o5NWjeGSDKZ/z5PV8j1jaKcy2S0N5pm3izDQayQdc4chRfInqkzN
Xw==
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
        ('MIIBdqADAgECAgIwOTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwlUZXN0Q2Vyd'
         'DEwHhcNMTEwOTA2MTk1MzI1WhcNMjEwOTAzMTk1MzI1WjAUMRIwEAYDVQQDEwlUZX'
         'N0Q2VydDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJrtL0+m9iFS2TD1a7i'
         'mdXgH+QPQFoZTeKsNlaEjBUSaYWRwXYa0+FK/LXYm2GPUzjkwTzCnLNay9dxQyFhp'
         'zXZayAVcSOqN5aHO2VRlV5JQBlBbcyJ6usOEBH8sB5bIEZhR/oIZqfo7jg4IQsYlJ'
         'MSDjj9/Ui+Pxo9hXsG5KUdrAgMBAAGjbjBsMB0GA1UdDgQWBBQyHAt4/VLMPxgKRQ'
         'W9f7eQL/aJgTA9BgNVHSMENjA0gBQyHAt4/VLMPxgKRQW9f7eQL/aJgaEYpBYwFDE'
         'SMBAGA1UEAxMJVGVzdENlcnQxggIwOTAMBgNVHRMEBTADAQH/')
         )
    self.assertEqual(
        _b64(x.GetSignatureData()),
        ('LDL1dAsoARGNo5E5w/6yeCWzfsgG6R7dexVItZPe9sMOBd4oKyJ3xeqYJPsfOuh1k'
         'L62bwFyT3TJBuldBiGjkZjWhVcgB7vWwGw0wmDK4oSGJ8/gj0byvKOTVo3hkgymf8'
         '+T1fI9Y2inMtktDeaZt4sw0GskHXOHIUXyJ6pMzV8=')
        )

  def testX509SubjectKnownOids(self):
    """Use a self-signed cert and load it. Check OIDs.

    The cert was generated as follows:
       openssl genrsa 1024 > host.key
       openssl req -new -x509 -subj \
         /CN=_cn_/C=US/L=_l_/ST=NY/O=_o_/OU=_ou_/emailAddress=_emailaddress_/DC=_dc_ \
         -nodes -sha1 \
         -days 365 -key host.key -set_serial 12345 > host.cert
    """
    s = """
-----BEGIN CERTIFICATE-----
MIIC2zCCAkSgAwIBAgICMDkwDQYJKoZIhvcNAQEFBQAwgYkxDTALBgNVBAMMBF9j
bl8xCzAJBgNVBAYTAlVTMQwwCgYDVQQHDANfbF8xCzAJBgNVBAgMAk5ZMQwwCgYD
VQQKDANfb18xDTALBgNVBAsMBF9vdV8xHTAbBgkqhkiG9w0BCQEWDl9lbWFpbGFk
ZHJlc3NfMRQwEgYKCZImiZPyLGQBGRYEX2RjXzAeFw0xNDA3MTExNDU2MDhaFw0y
NDA3MDgxNDU2MDhaMIGJMQ0wCwYDVQQDDARfY25fMQswCQYDVQQGEwJVUzEMMAoG
A1UEBwwDX2xfMQswCQYDVQQIDAJOWTEMMAoGA1UECgwDX29fMQ0wCwYDVQQLDARf
b3VfMR0wGwYJKoZIhvcNAQkBFg5fZW1haWxhZGRyZXNzXzEUMBIGCgmSJomT8ixk
ARkWBF9kY18wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPMwxsyuen866REz
P4AZbErBkzCS0+aWSrz/Qy7Lup4/zESgcd1bDIiP22yn5/HKBfYoe06DzGfi0fV+
7a+K0alrJI1ZrH6TcmJnS7HNZo5cABwvpm3c7ddprPgtRqggMXj1fuMgEtwewoVi
qs7RYt7p4VGLoWuj4zFhzgl+LKrnAgMBAAGjUDBOMB0GA1UdDgQWBBTsXLjH3R1W
K5L+k9AmuqiOczoRLzAfBgNVHSMEGDAWgBTsXLjH3R1WK5L+k9AmuqiOczoRLzAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBANz4q1NtjB3e/Inh3exaky8i
HBrHDY2/3eVnU2bv/gPPdFxA3rFUpxoC7a15wiiVa9uvGeplqeJ9ioDJSTXkWkS1
AHtYlWyrqlLr3qziOWTTCQhMZBxLSLx1TUYkfeeiJIoA8ZBp5i9KyKRIiSdzR7qZ
ujvfJAGJoIOC4OIor+fk
-----END CERTIFICATE-----
"""
    x = x509.LoadCertificateFromPEM(s)
    x.CheckAll()
    self.assertEqual(
        ('CN=_cn_,C=US,L=_l_,ST=NY,O=_o_,OU=_ou_,'
         'emailAddress=_emailaddress_,DC=_dc_'), x.GetSubject())


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

  def testIsSignedBy(self):
    server_public_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIDUzCCAjugAwIBAgIBATANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJBVTET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMB4XDTE2MDUxMTE1MTkwMFoXDTI2MDUwOTE1MTkwMFowGDEWMBQGA1UE
AwwNc2ltaWFuLXNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMJp0aUHStaAs61hkFUcygA3C5Ka0QEImyvcKzgogMnzhJexTO7MZRTMOsoON59g
Ioqg/TJF7ms+0T0oaf/pPIX2IWuGfushBkAnbBftBuspa//bW3reV1CmEIa/mF1h
Bi05b5FGdYumkuB6CF+1PP6mlbiLkVRehXRs3ASd4ci8lPUrJj8cG0H6g1Af2jVw
O2Zxjc1l/V2hKWsJTS93NM/ht9lgHkqyJ4b96p/vGf9kvnt6b1G1W+GzRll2Z1RT
HYnsSNqjRE1DqEowT92SjIhK/4LlLNjQLHnk6XccAKEEMhD7Hjs2q+s5cHi2JGSl
FjOMpVdVLp57IYqlj5zCqhsCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhC
AQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFGOa
t7c4f4fp2stvyrxSKjfLNLMcMB8GA1UdIwQYMBaAFBOzAkUMv86yjxXr3IUqyy8u
QEFPMA0GCSqGSIb3DQEBBQUAA4IBAQBi5nOzyaCe3gowCfO6kvDgE93PLPdp3BMY
3gAvmjufEea4GiU/6ZLiuCVShGFOIcx7xj87zQysGjfgkn0iJvfkp9/zRefKhrRQ
XXlNIsEV06mQEdbL/so9sN0OGEC/jqXXhpRAXLVwHJ7HlkJGDeNgDrFCR/NHN4SQ
2ZdErYZQb/2d2iSaM3Vhw5MAtTDuwmwCfQLPqh88XJaImKHrGXWYDPmBPEqXCcjc
CFX7jUjNcZ/Htzft3Jj7JdBBQdSNROsNASmLDp93XVCF7nve/+g2NyctAupyo9HH
niF+vXLOKT7WC3olS6wI6+d1I+rEAaMCbcPC/mx2b0C3n+OThrAg
-----END CERTIFICATE-----
"""
    ca_public_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAI8pfqfWG6QIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwNTExMTUxMjQzWhcNMjYwNTA5MTUxMjQzWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAq6X3CKITuEGxmPnLbRTYjgvziYqkYOMhbhIMejmOQpg0hmpCpbnZRhI8
cYv/TB1Gzqx2Zjt632eMD8DqXTGFwkCq/CYuDyyfmB5FguAxjdMcPpzrouOeqNaB
WR0c20+SxaS0hYOMIkHGGolThdQHtS/52UqLanyRkCL0sp8XhoVI6g0JQ4jr9eYE
rjdnlRBK3nkQKulHhhbBpxBFBsnU3wNTNNc2a5tgiOrKl/4Xq4Lt5VMRMoE66P02
NnKOFOWAAzcOukWWkoAaGiRleHxEA9HkJnxUETLKj9GEzLrxee1IwWDaYkv0yOIM
KEJwFR7T0tQnwzUQ9USVFnpgl4LOrQIDAQABo1AwTjAdBgNVHQ4EFgQUE7MCRQy/
zrKPFevchSrLLy5AQU8wHwYDVR0jBBgwFoAUE7MCRQy/zrKPFevchSrLLy5AQU8w
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEASUYXxloSIB3fgHOD5rx2
RrzYMHW07/SOJPCNGIEDS7/QClxIpzPF34BpvyeCWh4sgunDtHHgRkQ/433qe9lc
ek5ixxSXVkYaIhb6dCJJNT5pKHBs7mwM/mi8H4bp2bpKIswvs2yBXug/2nkY7BK2
LFmEGaihdRhrOh6FSyWblQn5CUCNQSU5P+zo7BITrPHaJQhOR/cKf7dXCE4Q8glX
a07aShkzPd4p6RLauwdrWKvvJD4KgcdMN2h/XDVTdwPUIwro382p0NMyA46lUgn3
6ocQocuktfeNuYIDFqRPC7HKH1ihyoTS9XrfwyNennAIl5ODglMaYuBRI6OpxUAC
1Q==
-----END CERTIFICATE-----
"""
    ca_cert = x509.LoadCertificateFromPEM(ca_public_cert_pem)
    cert = x509.LoadCertificateFromPEM(server_public_cert_pem)
    cert.CheckValidity()
    self.assertTrue(cert.IsSignedBy(ca_cert))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
