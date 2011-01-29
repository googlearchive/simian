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

"""Module to deal with Mac hardware.

Contents:

  class SystemProfile:
    to read system profile and obtain its parameters
"""




import subprocess
from simian.mac.munki import plist


class Error(Exception):
  """Base class."""


class SystemProfilerError(Error):
  """Error when running system_profiler."""


class SystemProfile(object):
  def __init__(self):
    """Init."""
    self._profile = {}

  def _GetSystemProfilerOutput(self):
    try:
      s = subprocess.Popen(
          ['/usr/bin/system_profiler', '-XML'],
          stdout = subprocess.PIPE,
          stderr = subprocess.PIPE)
    except OSError, e:
      raise SystemProfilerError(str(e))
    (stdout, stderr) = s.communicate()
    rc = s.wait()

    if rc != 0:
      raise SystemProfilerError('%d: %s' % (rc, stderr))

    return stdout

  def _GetSystemProfile(self):
    sp_xml = self._GetSystemProfilerOutput()
    p = plist.ApplePlist(sp_xml)
    p.Parse()
    self._system_profile_xml = sp_xml
    self._system_profile = p.GetContents()

  def _FindSerialNumber(self):
    """Find system serial number."""
    for d in self._system_profile:
      if d['_dataType'] == 'SPHardwareDataType':
        for item in d['_items']:
          if 'serial_number' in item:
            self._profile['serial_number'] = item['serial_number']
            return

  def _FindMacAddresses(self):
    """Find MAC addresses for network adapters."""
    for d in self._system_profile:
      if d['_dataType'] == 'SPNetworkDataType':
        for item in d['_items']:
          if 'hardware' in item:
            if 'Ethernet' in item and 'MAC Address' in item['Ethernet']:
              if item['hardware'] == 'Ethernet':
                self._profile['ethernet_mac'] = item['Ethernet']['MAC Address']
              elif item['hardware'] == 'AirPort':
                self._profile['airport_mac'] = item['Ethernet']['MAC Address']
              elif item['hardware'] == 'FireWire':
                self._profile['firewire_mac'] = item['Ethernet']['MAC Address']

  def _FindBatteryInfo(self):
    """Find battery info."""
    for d in self._system_profile:
      if d['_dataType'] == 'SPPowerDataType':
        for item in d['_items']:
          if 'sppower_battery_model_info' in item:
            self._profile['battery_serial_number'] = (
              item['sppower_battery_model_info']
              ['sppower_battery_serial_number'])

  def _FindUSBDevices(self):
    """Find all USB devices."""
    for d in self._system_profile:
      if d['_dataType'] == 'SPUSBDataType':
        for item in d['_items']:
          if 'host_controller' in item:
            for usb_item in item['_items']:
              if usb_item['_name'].find('iSight') > -1:
                self._profile['isight_serial_number'] = (
                    usb_item.get('d_serial_num', 'unknown'))

  def _FindAll(self):
    """Find all properties from system profile."""
    self._GetSystemProfile()
    self._FindSerialNumber()
    self._FindMacAddresses()
    self._FindBatteryInfo()
    self._FindUSBDevices()

  def GetProfile(self):
    """Returns the system profile.

    Returns:
      dict, with some or all these keys = {
        'serial_number': str,
        'ethernet_mac': str,
        'airport_mac': str,
        'firewire_mac': str,
        'battery_serial_number': str,
        'isight_serial_number': str,
      }
    """
    if not self._profile:
      self._FindAll()
    return self._profile


def main():
  sp = SystemProfile()
  p = sp.GetProfile()
  for k in p:
    print '%s: %s' % (k, p[k])


if __name__ == '__main__':
  main()