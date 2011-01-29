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

"""client module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.client import client


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


class SimianClient(mox.MoxTestBase):
  """Test SimianClient class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.client = client.SimianClient()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testIsPackageUploadNecessaryWhenNew(self):
    """Test _IsPackageUploadNecessary()."""
    filename = 'pkgname.dmg'
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
    filename = 'pkgname.dmg'
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
    filename = 'pkgname.dmg'
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
    filename = 'pkgname.dmg'
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
    filename = 'pkgname.dmg'
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

  def testUploadMunkiPackageWhenInstaller(self):
    """Test UploadMunkiPackage()."""
    filename = 'filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hook = None
    pkginfo_dict = {
      'installer_item_size': 'size',
      'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(client.os.path, 'basename')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    client.os.path.basename(filename).AndReturn(filename)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
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
            install_types, pkginfo_hook=pkginfo_hook))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenUninstaller(self):
    """Test UploadMunkiPackage()."""
    filename = 'filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hook = None
    pkginfo_dict = {
      'uninstaller_item_size': 'size',
      'uninstaller_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(client.os.path, 'basename')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    client.os.path.basename(filename).AndReturn(filename)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
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
            install_types, pkginfo_hook=pkginfo_hook))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookTrue(self):
    """Test UploadMunkiPackage()."""
    filename = 'filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hook = self.mox.CreateMockAnything()
    pkginfo_dict = {
      'installer_item_size': 'size',
      'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(client.os.path, 'basename')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    client.os.path.basename(filename).AndReturn(filename)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hook(pkginfo).AndReturn(True)
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
            install_types, pkginfo_hook=pkginfo_hook))
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookFalse(self):
    """Test UploadMunkiPackage()."""
    filename = 'filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hook = self.mox.CreateMockAnything()
    pkginfo_dict = {
      'installer_item_size': 'size',
      'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(client.os.path, 'basename')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    client.os.path.basename(filename).AndReturn(filename)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hook(pkginfo).AndReturn(False)

    self.mox.ReplayAll()
    self.assertRaises(
        client.client.SimianClientError,
        self.client.UploadMunkiPackage,
        filename, description, display_name, catalogs, manifests, install_types,
        pkginfo_hook=pkginfo_hook)
    self.mox.VerifyAll()

  def testUploadMunkiPackageWhenHookObject(self):
    """Test UploadMunkiPackage()."""
    filename = 'filename'
    description = 'desc'
    display_name = 'dn'
    catalogs = 'catalogs'
    manifests = 'manifests'
    install_types = 'install_types'
    pkginfo = self.mox.CreateMockAnything()
    pkginfo_hook = self.mox.CreateMockAnything()
    pkginfo_dict = {
      'installer_item_size': 'size',
      'installer_item_hash': 'hash',
    }
    response = 'http response'

    self.mox.StubOutWithMock(client.os.path, 'basename')
    self.mox.StubOutWithMock(self.client, '_LoadPackageInfo')
    self.mox.StubOutWithMock(self.client, 'UploadPackage')

    client.os.path.basename(filename).AndReturn(filename)
    self.client._LoadPackageInfo(
        filename, description, display_name, catalogs).AndReturn(pkginfo)
    pkginfo_hook(pkginfo).AndReturn(pkginfo)
    pkginfo.Parse().AndReturn(True)
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
            install_types, pkginfo_hook=pkginfo_hook))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()