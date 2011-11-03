#!/usr/bin/env python
# 
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""uuid module tests."""



from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.client import uuid


class UuidModuleTest(mox.MoxTestBase):
  """Test uuid module."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class MachineUuidTest(mox.MoxTestBase):
  """Test MachineUuid class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.muuid = uuid.MachineUuid()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testCheckPropertyValue(self):
    """Test _CheckPropertyValue()."""
    self.muuid.REGEX['foo'] = self.mox.CreateMockAnything()
    self.muuid.REGEX['foo'].match('bar').AndReturn(True)
    self.muuid.REGEX['foo'].match('bad').AndReturn(None)

    self.mox.ReplayAll()
    self.muuid._CheckPropertyValue('foo', 'bar')
    self.assertRaises(
        ValueError, self.muuid._CheckPropertyValue, 'foo', 'bad')
    self.mox.VerifyAll()

  def testSetGenericString(self):
    """Test _SetGenericString()."""
    self.mox.StubOutWithMock(self.muuid, '_CheckPropertyValue')
    self.muuid._CheckPropertyValue('foo', 'value').AndReturn(None)

    self.mox.ReplayAll()
    self.muuid._SetGenericString('foo', 'value')
    self.assertEqual(self.muuid._properties['foo'], 'value')
    self.mox.VerifyAll()

  def testSetGenericList(self):
    """Test _SetGenericList()."""
    self.mox.StubOutWithMock(self.muuid, '_CheckPropertyValue')
    self.muuid._CheckPropertyValue('eth', 'mac0').AndReturn(None)
    self.muuid._CheckPropertyValue('eth', 'mac1').AndReturn(None)
    self.muuid._CheckPropertyValue('eth', 'mac4').AndReturn(None)
    self.muuid._CheckPropertyValue('eth', 'mac2').AndReturn(None)
    self.muuid._CheckPropertyValue('eth', 'macinvalid').AndRaise(ValueError)

    self.mox.ReplayAll()
    self.muuid._SetGenericList('eth', 0, 'mac0')
    self.assertEqual(self.muuid._properties['eth'], ['mac0'])
    self.muuid._SetGenericList('eth', 1, 'mac1')
    self.assertEqual(self.muuid._properties['eth'], ['mac0', 'mac1'])
    self.muuid._SetGenericList('eth', 4, 'mac4')
    self.assertEqual(
        self.muuid._properties['eth'],
        ['mac0', 'mac1', None, None, 'mac4'])
    self.muuid._SetGenericList('eth', 2, 'mac2')
    self.assertEqual(
        self.muuid._properties['eth'],
        ['mac0', 'mac1', 'mac2', None, 'mac4'])
    self.assertRaises(
        ValueError,
        self.muuid._SetGenericList, 'eth', 2, 'macinvalid')
    self.assertEqual(
        self.muuid._properties['eth'],
        ['mac0', 'mac1', 'mac2', None, 'mac4'])
    self.mox.VerifyAll()

  def testSetEthernetMac(self):
    """Test SetEthernetMac()."""
    self.mox.StubOutWithMock(self.muuid, '_SetGenericList')
    self.muuid._SetGenericList('eth', 0, 'mac')
    self.mox.ReplayAll()
    self.muuid.SetEthernetMac(0, 'MAC')
    self.mox.VerifyAll()

  def testSetWirelessMac(self):
    """Test SetWirelessMac()."""
    self.mox.StubOutWithMock(self.muuid, '_SetGenericList')
    self.muuid._SetGenericList('eth', 0, 'mac')
    self.mox.ReplayAll()
    self.muuid.SetWirelessMac(0, 'MAC')
    self.mox.VerifyAll()

  def testSetHardwareId(self):
    """Test SetHardwareId()."""
    self.mox.StubOutWithMock(self.muuid, '_SetGenericList')
    self.muuid._SetGenericString('hwid', 'hwid')
    self.mox.ReplayAll()
    self.muuid.SetHardwareId('hwid')
    self.mox.VerifyAll()

  def testGenerateMachinePropertyUuid(self):
    """Test _GenerateMachinePropertyUuid()."""
    self.assertEqual(
        'foo%sbar' % self.muuid.PAIR_SET,
        self.muuid._GenerateMachinePropertyUuid('foo','bar'))

  def testGenerateMachineUuid(self):
    """Test GenerateMachineUuid()."""
    self.mox.StubOutWithMock(self.muuid, '_GenerateMachinePropertyUuid')
    self.muuid._properties['eth'] = ['mac']
    self.muuid._GenerateMachinePropertyUuid('eth', 'mac').AndReturn('foo')
    self.mox.ReplayAll()
    self.assertEqual('foo', self.muuid.GenerateMachineUuid())
    self.mox.VerifyAll()

  def testGenerateMachineUuidMedium(self):
    """Test GenerateMachineUuid()."""
    # one ethernet
    muuid = uuid.MachineUuid()
    muuid.SetEthernetMac(2, '00:01:02:03:04:05')
    machineuuid = muuid.GenerateMachineUuid()
    self.assertEqual('eth=00:01:02:03:04:05', muuid.GenerateMachineUuid())

    # one wireless
    muuid = uuid.MachineUuid()
    muuid.SetWirelessMac(1, '00:01:02:03:04:05')
    machineuuid = muuid.GenerateMachineUuid()
    self.assertEqual('eth=00:01:02:03:04:05', muuid.GenerateMachineUuid())

    # ethernet and wireless, ethernet first
    muuid = uuid.MachineUuid()
    muuid.SetEthernetMac(0, '00:01:02:03:04:05')
    muuid.SetWirelessMac(1, '06:07:08:09:0a:0b')
    machineuuid = muuid.GenerateMachineUuid()
    self.assertEqual('eth=00:01:02:03:04:05', muuid.GenerateMachineUuid())

    # ethernet and wireless, wireless first
    muuid = uuid.MachineUuid()
    muuid.SetEthernetMac(1, '00:01:02:03:04:05')
    muuid.SetWirelessMac(0, '06:07:08:09:0a:0b')
    machineuuid = muuid.GenerateMachineUuid()
    self.assertEqual('eth=06:07:08:09:0a:0b', muuid.GenerateMachineUuid())

    # only a hardware ID
    muuid = uuid.MachineUuid()
    muuid.SetHardwareId('abc')
    machineuuid = muuid.GenerateMachineUuid()
    self.assertEqual('hwid=abc', muuid.GenerateMachineUuid())

    # not enough info
    muuid = uuid.MachineUuid()
    self.assertRaises(
        uuid.GenerateMachineUuidError,
        muuid.GenerateMachineUuid)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()