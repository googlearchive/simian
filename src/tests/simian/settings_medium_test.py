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

"""settings module medium tests."""



import os
import tempfile

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
os.environ['____TESTING_SETTINGS_MODULE'] = 'yes'
from simian import settings
del(os.environ['____TESTING_SETTINGS_MODULE'])
from tests.simian import settings_test


class BaseSettingsTest(settings_test.BaseSettingsTestBase):
  """Test BaseSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.BaseSettings

  def testCheckValuePemX509Cert(self):
    """Test _CheckValuePemX509Cert()."""
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
    self.settings.CheckValuePemX509Cert('k', pem)

  def testCheckValuePemRsaPrivateKey(self):
    """Test _CheckValuePemRsaPrivateKey()."""
    pem = """
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC4PKVPk5XnZczXEHKgLAPraMV/8lYao8VPL861zdu7ex/1HGWj
UoZglIW18uFWnox5olfGLSmTuuqUXFerCPSRX8i2eWgOgtadbGO1WGjI3Or+/lIC
Vzze03ced37oqnb5c4wHFahQZYWLp/tX0UMLrrX0ziM1dGl3ewn6LCKOJwIDAQAB
AoGAUf8r0+7rmMFGGbHIUmFEnVFUFU3V5KVe+49bgK7OTPLPlle9JKNmCzYPDJu8
jsCh5MDML/eJuaZHISC4I/coYYnIdMSCjKal429wVqp9w0yCe+iuyT0mb0VTO8Nz
VmbVLLCAzJw9tTg6ETD63e7qTO8lEfUXbEF3gfGlI15OGoECQQDf3t61tFqmFLqo
fUWS/xJIg1GfrT27L1ZS3vWOf91C70Ez++EZwnGjRB9lQMLj/1k1wCfj7FukW6BJ
Khs+4xxtAkEA0q2cq8PXc0YUkgPfdOit7GcKp/5YGDGnkvfsC9SMgkASEoH9kRUK
hSz6askOK669V801Be/IUlaNY83+Ek7QYwJBAMnZFxDaBomMUygrmxmIpiF/VY8V
En29lqWtpdXP792z/yQxzKn/KZq9h1kx5QbRaswN72mP6KjufDy7nEk9WJkCQQCy
mjnyp8FT2TqBGsVqcANaIXS4PHhkclv0zTcQRG2l0jk/9XGIeEUF576XnsDjqWyd
LbtgwAmcPAH7dVuKG8SvAkBst9GgixxLGPr2uJYSkmBqvIUENwBzu1r5nsQU9Etn
8VzOUazBM2nEvMne0+bTe82szTBAkbbT2uXW7C13h7Ve
-----END RSA PRIVATE KEY-----
"""
    self.settings.CheckValuePemRsaPrivateKey('k', pem)


class FilesystemSettingsTest(settings_test.BaseSettingsTestBase):
  """Test FilesystemSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.FilesystemSettings

  def testGetExternalConfiguration(self):
    """Test loading config from .cfg file."""
    path = tempfile.mkdtemp()

    self.settings._path = path
    settings_filename = os.path.join(path, 'settings.cfg')

    sf = open(settings_filename, 'w')
    sf.write('[settings]\n')
    sf.write('foo = \'bar\'\n')
    sf.close()

    self.assertEqual('bar', self.settings.FOO)
    self.assertRaises(AttributeError, getattr, self.settings, 'OTHER')

    os.unlink(settings_filename)
    os.rmdir(path)

  def testGetExternalConfigurationPem(self):
    """Test loading pem from file."""
    path = tempfile.mkdtemp()

    self.settings._path = path
    ssl_path = os.path.join(path, 'ssl')
    os.mkdir(ssl_path, 0755)
    pem_filename = os.path.join(ssl_path, 'ca_public_cert.pem')

    # Note that this pem is purposefully malformed to prove that we
    # don't validate after value is already in the file.
    sf = open(pem_filename, 'w')
    sf.write('x')
    sf.close()

    self.assertEqual('x', self.settings.CA_PUBLIC_CERT_PEM)
    self.assertRaises(ValueError, self.settings.CheckValidation)

    os.unlink(pem_filename)
    os.rmdir(ssl_path)
    os.rmdir(path)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
