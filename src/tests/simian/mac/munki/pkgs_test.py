#!/usr/bin/env python
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
"""pkgs module tests."""

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.munki import pkgs


class MunkiPackageInfoTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.mpi = pkgs.MunkiPackageInfo()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def MockOut(self, method_name, args=None):
    self.mox.StubOutWithMock(self.mpi, method_name)

  def testIsOSX(self):
    """Test IsOSX()."""
    mock_uname = self.mox.CreateMockAnything()
    self.stubs.Set(pkgs.os, 'uname', mock_uname)
    mock_uname().AndReturn(['Darwin', 'foo'])
    mock_uname().AndReturn(['NotDarwin', 'foo'])
    self.mox.ReplayAll()
    self.assertTrue(self.mpi.IsOSX())
    self.assertFalse(self.mpi.IsOSX())
    self.mox.VerifyAll()

  def testGetMunkiPath(self):
    """Test _GetMunkiPath()."""
    base_path = self.mpi.munki_path
    filename = 'bar'
    joined = '/'.join([base_path, filename])
    mock_join = self.mox.CreateMockAnything()
    self.stubs.Set(pkgs.os.path, 'join', mock_join)
    mock_join(base_path, filename).AndReturn(joined)
    self.mox.ReplayAll()
    self.assertEqual(joined, self.mpi._GetMunkiPath(filename))
    self.mox.VerifyAll()

  def testVerifyMunkiInstall(self):
    """Test VerifyMunkiInstall()."""
    self.MockOut('IsOSX')
    self.mpi.IsOSX().AndReturn(True)
    self.mox.StubOutWithMock(pkgs.os.path, 'isdir')
    pkgs.os.path.isdir(self.mpi.munki_path).AndReturn(True)
    self.mox.StubOutWithMock(pkgs.os.path, 'isfile')

    self.MockOut('_GetMunkiPath')
    for f in self.mpi.REQUIRED_MUNKI_BINS:
      self.mpi._GetMunkiPath(f).AndReturn(f)
      pkgs.os.path.isfile(f).AndReturn(True)

    self.mox.ReplayAll()
    self.mpi.VerifyMunkiInstall()
    self.assertTrue(self.mpi.munki_install_verified)
    self.mpi.VerifyMunkiInstall()
    self.mox.VerifyAll()

  def testCreateFromPackage(self):
    """Test CreateFromPackage()."""
    makepkginfo = '/tmp/makepkginfo'
    catalogs = ['testing', 'stable']
    filename = 'foo'
    description = 'foo package description!!'
    display_name = 'Display Name'
    stdout = 'foo xml'
    stderr = ''
    status = 0
    args = [makepkginfo, filename, '--description=%s' % description,
            '--displayname=%s' % display_name,
            '--catalog=testing', '--catalog=stable']

    self.stubs.Set(
        pkgs.plist, 'MunkiPackageInfoPlist', self.mox.CreateMockAnything())
    mock_plist = self.mox.CreateMockAnything()
    self.MockOut('VerifyMunkiInstall')
    self.MockOut('_GetMunkiPath')
    self.mpi.VerifyMunkiInstall().AndReturn(None)
    self.mpi._GetMunkiPath(pkgs.MAKEPKGINFO).AndReturn(makepkginfo)
    mock_popen = self.mox.CreateMockAnything()
    self.stubs.Set(pkgs, 'subprocess', self.mox.CreateMock(pkgs.subprocess))
    pkgs.subprocess.Popen(
        args,
        stdin=None, stdout=pkgs.subprocess.PIPE, stderr=pkgs.subprocess.PIPE,
        close_fds=True,
        shell=False).AndReturn(mock_popen)
    mock_popen.communicate(None).AndReturn((stdout, stderr))
    mock_popen.poll().AndReturn(status)
    pkgs.plist.MunkiPackageInfoPlist(stdout).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)

    self.mox.ReplayAll()
    self.mpi.CreateFromPackage(filename, description, display_name, catalogs)
    self.assertEqual(self.mpi.filename, filename)
    self.mox.VerifyAll()

  def testCreateFromPackageError(self):
    """Test CreateFromPackage()."""
    makepkginfo = '/tmp/makepkginfo'
    catalogs = ['testing', 'stable']
    filename = 'foo'
    description = 'foo package description!'
    display_name = 'Display Name'
    stdout = ''
    stderr = 'zomg error'
    status = 123
    args = [makepkginfo, filename, '--description=%s' % description,
            '--displayname=%s' % display_name,
            '--catalog=testing', '--catalog=stable']

    self.MockOut('VerifyMunkiInstall')
    self.MockOut('_GetMunkiPath')
    self.mpi.VerifyMunkiInstall().AndReturn(None)
    self.mpi._GetMunkiPath(pkgs.MAKEPKGINFO).AndReturn(makepkginfo)
    mock_popen = self.mox.CreateMockAnything()
    self.stubs.Set(pkgs, 'subprocess', self.mox.CreateMock(pkgs.subprocess))
    pkgs.subprocess.Popen(
        args,
        stdin=None, stdout=pkgs.subprocess.PIPE, stderr=pkgs.subprocess.PIPE,
        close_fds=True,
        shell=False).AndReturn(mock_popen)
    mock_popen.communicate(None).AndReturn((stdout, stderr))
    mock_popen.poll().AndReturn(status)

    self.mox.ReplayAll()
    try:
      self.mpi.CreateFromPackage(filename, description, display_name, catalogs)
      self.fail('CreateFromPackage() should NOT return here')
    except pkgs.Error, e:
      self.assertEqual(
          e.args[0],
          ('makepkginfo: exit status %d, stderr=%s' % (status, stderr)))
    self.mox.VerifyAll()

  def testGetPlist(self):
    """Test GetPlist()."""
    self.mpi.plist = 'foo'
    self.assertEqual(self.mpi.GetPlist(), 'foo')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
