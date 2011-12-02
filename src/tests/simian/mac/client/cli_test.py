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

  def testPackageInfoTemplateHook(self):
    """Test PackageInfoTemplateHook()."""

    # This looks ugly, but it actually makes this test way simpler.
    # We create a new dict class with the extra methods we need to add
    # to simulate a plist.ApplePlist in the class. This avoids mocking out
    # a bunch of __contains__ __getitem__ __setitem__ calls below after
    # mock_template.GetContents(). It is just dictionary ops anyway.

    class EasyTestDict(dict):
      def Parse(self):
        raise NotImplementedError
      def GetContents(self):
        raise NotImplementedError
      def SetContents(self, x):
        raise NotImplementedError
      def SetChanged(self, x=True):
        raise NotImplementedError
      def Validate(self):
        raise NotImplementedError

    pkginfo = {
      'foo': 1,
      'zoo': 9,
    }
    template = {
      'foo': 2,
      'bar': 3,
    }
    combined = {
      'foo': 2,
      'zoo': 9,
      'bar': 3,
    }
    self.mpcc.config['template_pkginfo'] = 'filename'

    self.mox.StubOutWithMock(cli.plist, 'ApplePlist')

    mock_pkginfo = EasyTestDict()
    mock_input_pkginfo = self.mox.CreateMockAnything()
    mock_open = self.mox.CreateMockAnything()
    mock_template = EasyTestDict()

    self.mox.StubOutWithMock(mock_pkginfo, 'SetChanged')
    self.mox.StubOutWithMock(mock_pkginfo, 'SetContents')
    self.mox.StubOutWithMock(mock_pkginfo, 'Validate')
    self.mox.StubOutWithMock(mock_template, 'Parse')
    self.mox.StubOutWithMock(mock_template, 'GetContents')

    # prep the template with values from dict
    for k in template:
      mock_template[k] = template[k]

    # prep the pkginfo with values from dict
    for k in pkginfo:
      mock_pkginfo[k] = pkginfo[k]

    mock_input_pkginfo.copy().AndReturn(mock_pkginfo)

    mock_open('filename', 'r').AndReturn(mock_open)
    mock_open.read().AndReturn('plist_xml')
    cli.plist.ApplePlist('plist_xml').AndReturn(mock_template)
    mock_template.Parse().AndReturn(None)
    mock_template.GetContents().AndReturn(pkginfo)

    # dictionary value copying occurs here in real code, no mocks
    # visible here.

    mock_pkginfo.Validate().AndReturn(None)

    self.mox.ReplayAll()
    output = self.mpcc.PackageInfoTemplateHook(
        mock_input_pkginfo, open_=mock_open)
    self.assertEqual(output, combined)
    self.mox.VerifyAll()

  def testEditPackageInfoWhenUpdatingManifests(self):
    """Test EditPackageInfo() when updating manifests value."""
    self.mox.StubOutWithMock(self.mpcc, 'ValidatePackageConfig')
    self.mpcc.client = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(cli.plist, 'MunkiPackageInfoPlist')

    filename = 'file.dmg'
    filepath = '/path/to/%s' % filename
    description = 'snark!'
    display_name = None
    pkginfo_name = None
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
        'template_pkginfo': None,
    }

    self.mpcc.ValidatePackageConfig(defaults=False).AndReturn((
        filepath, description, display_name, pkginfo_name, manifests, catalogs,
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
    pkginfo_name = None
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
        'template_pkginfo': None,
    }

    self.mpcc.ValidatePackageConfig(defaults=False).AndReturn((
        filepath, description, display_name, pkginfo_name, manifests, catalogs,
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

  def testValidatePackageConfig(self):
    """Test ValidatePackageConfig()."""
    self.mpcc.config = {
      'manifests': 'stable,testing',
      'catalogs': 'testing,unstable',
      'install_types': 'managed_installs',
      'package': 'p',
      'description': 'd',
      'display_name': 'dn',
      'name': None,
      'unattended_install': None,
      'unattended_uninstall': None,
    }
    self.mox.ReplayAll()
    self.assertEqual(
        (
            'p', 'd', 'dn', None,
            ['stable', 'testing'], ['testing', 'unstable'],
            ['managed_installs'],
            False, False
        ),
        self.mpcc.ValidatePackageConfig())
    self.mox.VerifyAll()

  def testValidatePackageConfigWhenNoCatalogsSpecified(self):
    """Test ValidatePackageConfig().

    In this test we are verifying that ValidatePackageConfig() will auto
    supply a default catalogs value "unstable" when no value is supplied.

    Less importantly, we are also verifying that when no manifests value
    is supplied, none is created.
    """
    self.mpcc.config = {
      'manifests': None,
      'catalogs': None,
      'install_types': 'managed_installs',
      'package': 'p',
      'description': 'd',
      'display_name': 'dn',
      'name': None,
      'unattended_install': None,
      'unattended_uninstall': None,
    }
    self.mox.ReplayAll()
    self.assertEqual(
        (
            'p', 'd', 'dn', None,
            None, ['unstable'], ['managed_installs'],
            False, False
        ),
        self.mpcc.ValidatePackageConfig())
    self.mox.VerifyAll()

  def testValidatePackageConfigWhenEmptyManifestsSpecified(self):
    """Test ValidatePackageConfig().

    In this test we are verifying that when the manifests value is
    set to empty/none, the manifest list output is [].
    """
    self.mpcc.config = {
      'manifests': cli.LIST_EMPTY,
      'catalogs': 'unstable',
      'install_types': 'managed_installs',
      'package': 'p',
      'description': 'd',
      'display_name': 'dn',
      'name': 'fooname',
      'unattended_install': None,
      'unattended_uninstall': None,
    }
    self.mox.ReplayAll()
    self.assertEqual(
        (
            'p', 'd', 'dn', 'fooname',
            [], ['unstable'], ['managed_installs'],
            None, None
        ),
        self.mpcc.ValidatePackageConfig(defaults=False))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()