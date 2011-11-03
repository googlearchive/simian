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

"""cli module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.client import cli


class CliModuleTest(mox.MoxTestBase):
  """Test cli module."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class SimianCliClient(mox.MoxTestBase):
  """Test SimianCliClient class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.mpcc = cli.SimianCliClient()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testInit(self):
    self.assertEqual(self.mpcc.opts, [])
    self.assertEqual(self.mpcc.args, [])
    self.assertEqual(type(self.mpcc.config), dict)
    self.assertEqual(self.mpcc.command, None)

  # TODO(user): This module needs a lot more tests.

  def testEditPackageInfoWhenUpdatingManifests(self):
    """Test EditPackageInfo() when updating manifests value."""
    self.mox.StubOutWithMock(self.mpcc, 'ValidatePackageConfig')
    self.mpcc.client = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(cli.plist, 'MunkiPackageInfoPlist')

    filename = 'file.dmg'
    filepath = '/path/to/%s' % filename
    description = 'snark!'
    display_name = None
    manifests = ['unstable', 'testing', 'stable']
    # catalogs this package is already in
    pkg_catalogs = ['unstable', 'testing', 'stable']
    catalogs = None
    install_types = None
    unattended_install = None
    unattended_uninstall = None
    sha256_hash = 'hash'
    pkginfo_xml = 'xml'

    mock_plist = self.mox.CreateMockAnything()

    self.mpcc.config = {
        'edit_pkginfo': None,
    }

    self.mpcc.ValidatePackageConfig(defaults=False).AndReturn((
        filepath, description, display_name, manifests, catalogs,
        install_types, unattended_install, unattended_uninstall))
    self.mpcc.client.GetPackageInfo(filename, get_hash=True).AndReturn((
        sha256_hash, pkginfo_xml))

    cli.plist.MunkiPackageInfoPlist(pkginfo_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)

    mock_plist.SetDescription(description).AndReturn(None)

    mock_plist.GetContents().AndReturn({'catalogs': pkg_catalogs})

    mock_plist.GetXml().AndReturn(pkginfo_xml)

    cli.plist.MunkiPackageInfoPlist(pkginfo_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)

    kwargs = {
        'got_hash': sha256_hash,
        'manifests': manifests,
    }

    self.mpcc.client.PutPackageInfo(filename, pkginfo_xml, **kwargs).AndReturn(
        None)

    self.mox.ReplayAll()
    self.mpcc.EditPackageInfo()
    self.mox.VerifyAll()

  def testEditPackageInfoWhenUpdatingManifestsCatalogMismatch(self):
    """Test EditPackageInfo() when updating manifests non-sync w catalogs. """
    self.mox.StubOutWithMock(self.mpcc, 'ValidatePackageConfig')
    self.mpcc.client = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(cli.plist, 'MunkiPackageInfoPlist')

    filename = 'file.dmg'
    filepath = '/path/to/%s' % filename
    description = 'snark!'
    display_name = None
    manifests = ['stable']
    # catalogs this package is already in
    pkg_catalogs = ['unstable']
    catalogs = None
    install_types = None
    unattended_install = None
    unattended_uninstall = None
    sha256_hash = 'hash'
    pkginfo_xml = 'xml'

    mock_plist = self.mox.CreateMockAnything()

    self.mpcc.config = {
        'edit_pkginfo': None,
    }

    self.mpcc.ValidatePackageConfig(defaults=False).AndReturn((
        filepath, description, display_name, manifests, catalogs,
        install_types, unattended_install, unattended_uninstall))
    self.mpcc.client.GetPackageInfo(filename, get_hash=True).AndReturn((
        sha256_hash, pkginfo_xml))

    cli.plist.MunkiPackageInfoPlist(pkginfo_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)

    mock_plist.SetDescription(description).AndReturn(None)

    mock_plist.GetContents().AndReturn({'catalogs': pkg_catalogs})

    self.mox.ReplayAll()
    self.assertRaises(cli.CliError, self.mpcc.EditPackageInfo)
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()