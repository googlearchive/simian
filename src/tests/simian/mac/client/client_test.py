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

"""client module tests."""



import logging
logging.basicConfig(filename='/dev/null')

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.client import client


class ClientModuleTest(mox.MoxTestBase):
  """Test module level functions in client."""
  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class BaseSimianClientTest(mox.MoxTestBase):
  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.client = client.BaseSimianClient()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testGetSystemRootCACertChain(self):
    """Test GetSystemRootCACertChain()."""
    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    self.mox.StubOutWithMock(
        client.client.SimianClient, 'GetSystemRootCACertChain', True)
    argv = [
      '/usr/bin/security',
      'find-certificate', '-a',
      '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'
    ]
    stdout = 'output'
    stderr = ''
    rc = 0
    mock_p = self.mox.CreateMockAnything()
    client.client.SimianClient.GetSystemRootCACertChain(
        self.client).AndReturn('')
    client.subprocess.Popen(
        argv,
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndReturn((stdout, stderr))
    mock_p.wait().AndReturn(rc)

    self.mox.ReplayAll()
    self.assertEqual(stdout, self.client.GetSystemRootCACertChain())
    self.mox.VerifyAll()

  def testGetSystemRootCACertChainWhenError(self):
    """Test GetSystemRootCACertChain()."""
    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    self.mox.StubOutWithMock(
        client.client.SimianClient, 'GetSystemRootCACertChain', True)
    argv = [
      '/usr/bin/security',
      'find-certificate', '-a',
      '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'
    ]
    stdout = 'output'
    stderr = ''
    rc = 1
    mock_p = self.mox.CreateMockAnything()
    client.client.SimianClient.GetSystemRootCACertChain(
        self.client).AndReturn('')
    client.subprocess.Popen(
        argv,
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndReturn((stdout, stderr))
    mock_p.wait().AndReturn(rc)

    self.mox.ReplayAll()
    self.assertEqual('', self.client.GetSystemRootCACertChain())
    self.mox.VerifyAll()

  def testGetSystemRootCACertChainWhenOSError(self):
    """Test GetSystemRootCACertChain()."""
    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    self.mox.StubOutWithMock(
        client.client.SimianClient, 'GetSystemRootCACertChain', True)
    argv = [
        '/usr/bin/security',
        'find-certificate', '-a',
        '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'
    ]
    client.client.SimianClient.GetSystemRootCACertChain(
        self.client).AndReturn('')
    client.subprocess.Popen(
        argv,
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndRaise(OSError)

    self.mox.ReplayAll()
    self.assertEqual('', self.client.GetSystemRootCACertChain())
    self.mox.VerifyAll()

  def testGetSystemProfile(self):
    """Test _GetSystemProfile()."""
    profile = 'profile'

    mock_profile = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(client.hw, 'SystemProfile')

    client.hw.SystemProfile(
        include_only=['network', 'system']).AndReturn(mock_profile)
    mock_profile.GetProfile().AndReturn(profile)

    self.mox.ReplayAll()
    self.assertEqual(profile, self.client._GetSystemProfile())
    self.mox.VerifyAll()


class SimianClient(mox.MoxTestBase):
  """Test SimianClient class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.client = client.SimianClient()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testIsDiskImageReadOnly(self):
    """Test _IsDiskImageReadOnly()."""
    filename = '/tmp/pkgname.dmg'
    stdout = 'foo\nFormat Description: UDIF read-only compressed (bzip2)\nbar\n'
    stderr = ''
    rc = 0

    mock_p = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    client.subprocess.Popen(
        ['/usr/bin/hdiutil', 'imageinfo', filename],
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndReturn((stdout, stderr))
    mock_p.wait().AndReturn(rc)

    self.mox.ReplayAll()
    self.assertTrue(self.client._IsDiskImageReadOnly(filename))
    self.mox.VerifyAll()

  def testIsDiskImageReadOnlyWhenReadWrite(self):
    """Test _IsDiskImageReadOnly()."""
    filename = '/tmp/pkgname.dmg'
    stdout = 'Format Description: UDIF read-write compressed (bzip2)\nfoo\n'
    stderr = ''
    rc = 0

    mock_p = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    client.subprocess.Popen(
        ['/usr/bin/hdiutil', 'imageinfo', filename],
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndReturn((stdout, stderr))
    mock_p.wait().AndReturn(rc)

    self.mox.ReplayAll()
    self.assertFalse(self.client._IsDiskImageReadOnly(filename))
    self.mox.VerifyAll()

  def testIsDiskImageReadOnlyWhenExecError(self):
    """Test _IsDiskImageReadOnly()."""
    filename = '/tmp/pkgname.dmg'

    mock_p = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    client.subprocess.Popen(
        ['/usr/bin/hdiutil', 'imageinfo', filename],
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndRaise(OSError)

    self.mox.ReplayAll()
    self.assertRaises(
        client.client.SimianClientError,
        self.client._IsDiskImageReadOnly, filename)
    self.mox.VerifyAll()

  def testIsDiskImageReadOnlyWhenNonZero(self):
    """Test _IsDiskImageReadOnly()."""
    filename = '/tmp/pkgname.dmg'
    stdout = 'Format Description: UDIF read-write compressed (bzip2)\nfoo\n'
    stderr = ''
    rc = 9

    mock_p = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(client.subprocess, 'Popen')
    client.subprocess.Popen(
        ['/usr/bin/hdiutil', 'imageinfo', filename],
        stdout=client.subprocess.PIPE,
        stderr=client.subprocess.PIPE).AndReturn(mock_p)
    mock_p.communicate().AndReturn((stdout, stderr))
    mock_p.wait().AndReturn(rc)

    self.mox.ReplayAll()
    self.assertRaises(
        client.client.SimianClientError,
        self.client._IsDiskImageReadOnly, filename)
    self.mox.VerifyAll()


  def testIsPackageUploadNecessaryWhenNew(self):
    """Test _IsPackageUploadNecessary()."""
    filename = '/tmp/pkgname.dmg'
    pkginfo = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.client, 'GetPackageInfo')

    self.client.GetPackageInfo(filename).AndRaise(
        client.client.SimianServerError)

    self.mox.ReplayAll()
    self.assertTrue(
        self.client._IsPackageUploadNecessary(filename, pkginfo))
    self.mox.VerifyAll()

  def testIsPackageUploadNecessaryWhenPlistParseError(self):
    """Test _IsPackageUploadNecessary()."""
    filename = '/tmp/pkgname.dmg'
    pkginfo = 'ha'
    cur_pkginfo = 'xml pkginfo data'
    mock_mpip = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.client, 'GetPackageInfo')
    self.stubs.Set(client.plist, 'MunkiPackageInfoPlist', mock_mpip)

    self.client.GetPackageInfo(filename).AndReturn(cur_pkginfo)
    mock_mpip(cur_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndRaise(client.plist.PlistError)

    self.mox.ReplayAll()
    self.assertTrue(
        self.client._IsPackageUploadNecessary(filename, pkginfo))
    self.mox.VerifyAll()

  def testIsPackageUploadNecessaryWhenHashMissing(self):
    """Test _IsPackageUploadNecessary()."""
    filename = '/tmp/pkgname.dmg'
    upload_pkginfo = self.mox.CreateMockAnything()
    upload_pkginfo_dict = {
      'installer_item_size': 1,
      'installer_item_hash': 'foobar',
    }
    cur_pkginfo = 'xml pkginfo data'
    pkginfo_plist = self.mox.CreateMockAnything()
    mock_mpip = self.mox.CreateMockAnything()
    pkginfo_dict = {'foo': 'bar'}

    self.mox.StubOutWithMock(self.client, 'GetPackageInfo')
    self.stubs.Set(client, 'plist', self.mox.CreateMock(client.plist))

    self.client.GetPackageInfo(filename).AndReturn(cur_pkginfo)
    client.plist.MunkiPackageInfoPlist(cur_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(pkginfo_dict)

    client.plist.MunkiPackageInfoPlist(upload_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(upload_pkginfo_dict)

    self.mox.ReplayAll()
    self.assertTrue(
        self.client._IsPackageUploadNecessary(filename, upload_pkginfo))
    self.mox.VerifyAll()

  def testIsPackageUploadNecessaryWhenHashDifferent(self):
    """Test _IsPackageUploadNecessary()."""
    filename = '/tmp/pkgname.dmg'
    orig_sha256_hash = 'haha hash 2'
    upload_pkginfo = self.mox.CreateMockAnything()
    upload_pkginfo_dict = {
      'installer_item_size': 1,
      'installer_item_hash': 'not %s' % orig_sha256_hash,
    }
    cur_pkginfo = 'xml pkginfo data'
    pkginfo_plist = self.mox.CreateMockAnything()
    mock_mpip = self.mox.CreateMockAnything()
    pkginfo_dict = {'installer_item_hash': orig_sha256_hash}

    self.mox.StubOutWithMock(self.client, 'GetPackageInfo')
    self.stubs.Set(client, 'plist', self.mox.CreateMock(client.plist))

    self.client.GetPackageInfo(filename).AndReturn(cur_pkginfo)
    client.plist.MunkiPackageInfoPlist(cur_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(pkginfo_dict)

    client.plist.MunkiPackageInfoPlist(upload_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(upload_pkginfo_dict)

    self.mox.ReplayAll()
    self.assertTrue(
        self.client._IsPackageUploadNecessary(filename, upload_pkginfo))
    self.mox.VerifyAll()

  def testIsPackageUploadNecessaryWhenHashSame(self):
    """Test _IsPackageUploadNecessary()."""
    filename = '/tmp/pkgname.dmg'
    orig_sha256_hash = 'haha hash 2'
    upload_pkginfo = self.mox.CreateMockAnything()
    upload_pkginfo_dict = {
        'uninstaller_item_size': 1,
        'uninstaller_item_hash': orig_sha256_hash,
    }
    cur_pkginfo = 'xml pkginfo data'
    pkginfo_plist = self.mox.CreateMockAnything()
    mock_mpip = self.mox.CreateMockAnything()
    pkginfo_dict = {'uninstaller_item_hash': orig_sha256_hash}

    self.mox.StubOutWithMock(self.client, 'GetPackageInfo')
    self.stubs.Set(client, 'plist', self.mox.CreateMock(client.plist))

    self.client.GetPackageInfo(filename).AndReturn(cur_pkginfo)
    client.plist.MunkiPackageInfoPlist(cur_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(pkginfo_dict)

    client.plist.MunkiPackageInfoPlist(upload_pkginfo).AndReturn(mock_mpip)
    mock_mpip.Parse().AndReturn(None)
    mock_mpip.GetContents().AndReturn(upload_pkginfo_dict)

    self.mox.ReplayAll()
    self.assertFalse(
       self.client._IsPackageUploadNecessary(filename, upload_pkginfo))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenNotReadOnlyDiskImage(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = None
    pkginfo_dict = {
        'installer_item_size': 'size',
        'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(False)

    self.mox.ReplayAll()
    self.assertRaises(
        client.client.SimianClientError,
        self.client.UploadMunkiPackage,
        filename, description, display_name, catalogs, manifests,
        install_types, pkginfo_hooks=pkginfo_hooks)
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenInstaller(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    pkginfo_name = 'fooname'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = None
    pkginfo_dict = {
        'installer_item_size': 'size',
        'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(True)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo.__setitem__('unattended_install', True).AndReturn(None)
    pkginfo.__setitem__('forced_install', True).AndReturn(None)
    pkginfo.__setitem__('name', pkginfo_name).AndReturn(None)
    pkginfo.Validate().AndReturn(None)
    pkginfo.GetXml().AndReturn('pkginfo xml')

    self.client.UploadPackage(
        filename, description, display_name, catalogs, manifests, install_types,
        'pkginfo xml').AndReturn((response, filename, catalogs, manifests))

    pkginfo.GetPackageName().AndReturn('pkg name')
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)

    self.mox.ReplayAll()
    self.assertEqual(
        (response, filename, 'pkg name', catalogs, manifests, 'size', 'hash'),
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, pkginfo_hooks=pkginfo_hooks, unattended_install=True,
            pkginfo_name=pkginfo_name))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenUninstaller(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = None
    pkginfo_dict = {
        'uninstaller_item_size': 'size',
        'uninstaller_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(True)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo.__setitem__('unattended_uninstall', True).AndReturn(None)
    pkginfo.__setitem__('forced_uninstall', True).AndReturn(None)
    pkginfo.Validate().AndReturn(None)
    pkginfo.GetXml().AndReturn('pkginfo xml')

    self.client.UploadPackage(
        filename, description, display_name, catalogs, manifests, install_types,
        'pkginfo xml').AndReturn((response, filename, catalogs, manifests))

    pkginfo.GetPackageName().AndReturn('pkg name')
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)

    self.mox.ReplayAll()
    self.assertEqual(
        (response, filename, 'pkg name', catalogs, manifests, 'size', 'hash'),
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, pkginfo_hooks=pkginfo_hooks,
            unattended_uninstall=True))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookTrue(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = [self.mox.CreateMockAnything()]
    pkginfo_dict = {
        'installer_item_size': 'size',
        'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(True)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hooks[0](pkginfo).AndReturn(True)
    pkginfo.Validate().AndReturn(None)
    pkginfo.GetXml().AndReturn('pkginfo xml')

    self.client.UploadPackage(
        filename, description, display_name, catalogs, manifests, install_types,
        'pkginfo xml').AndReturn((response, filename, catalogs, manifests))

    pkginfo.GetPackageName().AndReturn('pkg name')
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)

    self.mox.ReplayAll()
    self.assertEqual(
        (response, filename, 'pkg name', catalogs, manifests, 'size', 'hash'),
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, pkginfo_hooks=pkginfo_hooks))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookFalse(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = [self.mox.CreateMockAnything()]
    pkginfo_dict = {
        'installer_item_size': 'size',
        'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(True)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hooks[0](pkginfo).AndReturn(False)
    pkginfo.Validate().AndReturn(None)

    self.mox.ReplayAll()
    self.assertRaises(
        client.client.SimianClientError,
        self.client.UploadMunkiPackage,
        filename, description, display_name, catalogs, manifests, install_types,
        pkginfo_hooks=pkginfo_hooks)
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookObject(self):
    """Test UploadMunkiPackage()."""
    filename = '/tmp/filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hooks = [self.mox.CreateMockAnything()]
    pkginfo_dict = {
        'installer_item_size': 'size',
        'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(self.client, '_IsDiskImageReadOnly')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    self.client._IsDiskImageReadOnly(filename).AndReturn(True)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hooks[0](pkginfo).AndReturn(pkginfo)
    pkginfo.Validate().AndReturn(True)
    pkginfo.__getitem__('description').AndReturn(description)
    pkginfo.__getitem__('display_name').AndReturn(display_name)
    pkginfo.__getitem__('catalogs').AndReturn(catalogs)
    pkginfo.GetXml().AndReturn('pkginfo xml')

    self.client.UploadPackage(
        filename, description, display_name, catalogs, manifests, install_types,
        'pkginfo xml').AndReturn((response, filename, catalogs, manifests))

    pkginfo.GetPackageName().AndReturn('pkg name')
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)
    pkginfo.GetContents().AndReturn(pkginfo_dict)

    self.mox.ReplayAll()
    self.assertEqual(
        (response, filename, 'pkg name', catalogs, manifests, 'size', 'hash'),
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, pkginfo_hooks=pkginfo_hooks))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
