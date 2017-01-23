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
"""client module tests."""

import logging

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


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
