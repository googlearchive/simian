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
"""hw module tests."""

import mox
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.common import hw


class SystemProfileTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.sp = hw.SystemProfile()

  def tearDown(self):
    self.mox.UnsetStubs()

  def testInit(self):
    """Test __init__()."""
    self.assertEqual(self.sp._profile, {})
    self.assertEqual(self.sp._include_only, None)
    temp_sp = hw.SystemProfile(include_only='foo')
    self.assertEqual(temp_sp._include_only, 'foo')

  def testGetSystemProfilerOutput(self):
    """Test _GetSystemProfilerOutput()."""
    stdout = 'out'
    stderr = ''
    self.mox.StubOutWithMock(hw.subprocess, 'Popen', True)
    mock_sp = self.mox.CreateMockAnything()

    hw.subprocess.Popen(
        ['/usr/sbin/system_profiler', '-XML'],
        stdout=hw.subprocess.PIPE,
        stderr=hw.subprocess.PIPE).AndReturn(mock_sp)
    mock_sp.communicate().AndReturn((stdout, stderr))
    mock_sp.wait().AndReturn(0)

    hw.subprocess.Popen(
        ['/usr/sbin/system_profiler', '-XML', 'SPNetworkDataType'],
        stdout=hw.subprocess.PIPE,
        stderr=hw.subprocess.PIPE).AndReturn(mock_sp)
    mock_sp.communicate().AndReturn((stdout, stderr))
    mock_sp.wait().AndReturn(0)

    self.mox.ReplayAll()
    self.assertEqual(stdout, self.sp._GetSystemProfilerOutput())
    self.sp._include_only = ['network', 'unknown thing']
    self.assertEqual(stdout, self.sp._GetSystemProfilerOutput())
    self.mox.VerifyAll()

  def testGetSystemProfile(self):
    """Test _GetSystemProfile()."""
    sp_xml = 'foo'
    mock_plist = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.sp, '_GetSystemProfilerOutput')
    self.mox.StubOutWithMock(hw.plist, 'ApplePlist', True)

    self.sp._GetSystemProfilerOutput().AndReturn(sp_xml)
    hw.plist.ApplePlist(sp_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndReturn(None)
    mock_plist.GetContents().AndReturn('contents')

    self.mox.ReplayAll()
    self.sp._GetSystemProfile()
    self.assertEqual(self.sp._system_profile_xml, sp_xml)
    self.assertEqual(self.sp._system_profile, 'contents')
    self.mox.VerifyAll()

  def testGetSystemProfilePlistParseError(self):
    """Test _GetSystemProfile() with plist.Error raised when calling Parse()."""
    sp_xml = 'foo'
    mock_plist = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(self.sp, '_GetSystemProfilerOutput')
    self.mox.StubOutWithMock(hw.plist, 'ApplePlist', True)

    self.sp._GetSystemProfilerOutput().AndReturn(sp_xml)
    hw.plist.ApplePlist(sp_xml).AndReturn(mock_plist)
    mock_plist.Parse().AndRaise(hw.plist.Error)

    self.mox.ReplayAll()
    self.assertRaises(hw.SystemProfilerError, self.sp._GetSystemProfile)
    self.mox.VerifyAll()

  def testFindAll(self):
    """Test _FindAll()."""
    funcs = (
        '_GetSystemProfile',
        '_FindHDDSerial',
        '_FindMachineModel',
        '_FindSerialNumber',
        '_FindPlatformUuid',
        '_FindMacAddresses',
        '_FindBatteryInfo',
        '_FindUSBDevices')
    for func_name in funcs:
      self.mox.StubOutWithMock(self.sp, func_name)
      getattr(self.sp, func_name)().AndReturn(None)
    self.mox.ReplayAll()
    self.sp._FindAll()
    self.mox.VerifyAll()

  def testFindHddSerialWithNoNvme(self):
    self.mox.StubOutWithMock(self.sp, '_GetSystemProfilerOutput')
    self.sp._GetSystemProfilerOutput().AndReturn('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>_SPCommandLineArguments</key>
    <array>
      <string>/usr/sbin/system_profiler</string>
      <string>-nospawn</string>
      <string>-xml</string>
      <string>SPNVMeDataType</string>
      <string>-detailLevel</string>
      <string>full</string>
    </array>
    <key>_SPResponseTime</key>
    <real>0.2080950140953064</real>
    <key>_dataType</key>
    <string>SPNVMeDataType</string>
  </dict>
</array>
</plist>
'''.strip())
    self.mox.ReplayAll()
    self.sp._FindAll()
    self.mox.VerifyAll()

  def testGetProfile(self):
    """Test GetProfile()."""
    self.sp._profile = {}
    self.mox.StubOutWithMock(self.sp, '_FindAll')
    self.sp._FindAll().AndReturn(None)
    self.mox.ReplayAll()
    self.assertEqual({}, self.sp.GetProfile())
    self.mox.VerifyAll()

  def testGetProfileWhenReady(self):
    """Test GetProfile()."""
    self.sp._profile = 'foo'
    self.mox.ReplayAll()
    self.assertEqual('foo', self.sp.GetProfile())
    self.mox.VerifyAll()

  def testFindBatteryInfoWithMissingSerial(self):
    """Test _FindBatteryInfo() with a missing serial number."""
    # sppower_battery_model_info dict lacking sppower_battery_serial_number
    spd = [{
        '_dataType': 'SPPowerDataType',
        '_items': [{'fookey': 'foovalue', 'sppower_battery_model_info': {}}],
    }]
    self.sp._system_profile = spd
    self.sp._FindBatteryInfo()
    self.assertEqual('unknown', self.sp._profile['battery_serial_number'])


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
