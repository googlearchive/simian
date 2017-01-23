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

  DATA_TYPES = {
      'hardware': 'SPHardwareDataType',
      'network': 'SPNetworkDataType',
      'nvme': 'SPNVMeDataType',
      'parallelata': 'SPParallelATADataType',
      'power': 'SPPowerDataType',
      'serialata': 'SPSerialATADataType',
      'system': 'SPSystemDataType',
      'usb': 'SPUSBDataType',
  }

  def __init__(self, include_only=None):
    """Init.

    Args:
      include_only: list, optional, items from DATA_TYPES which will
          be the only data types requested from system profiler.
    """
    self._profile = {}
    self._include_only = include_only

  def _GetSystemProfilerOutput(self):
    argv = ['/usr/sbin/system_profiler', '-XML']

    if self._include_only:
      for data_type in self._include_only:
        if data_type in self.DATA_TYPES:
          argv.append(self.DATA_TYPES[data_type])

    try:
      s = subprocess.Popen(
          argv,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE)
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
    try:
      p.Parse()
    except plist.Error, e:
      raise SystemProfilerError('plist Parse() error: %s' % str(e))
    self._system_profile_xml = sp_xml
    self._system_profile = p.GetContents()

  def _GetDataTypeItems(self, data_type_key):
    """Returns the "_items" array inside a given data type dictionary.

    Args:
      data_type_key: str, key of self.DATA_TYPE containing the desired _items.
    Returns:
      list of items in the array, or an empty list if the data type is unknown
      or not found.
    """
    data_type = self.DATA_TYPES.get(data_type_key)
    for d in self._system_profile:
      if data_type and d.get('_dataType') == data_type and '_items' in d:
        return d['_items']
    return []

  def _FindHDDSerial(self):
    """Find the primary Hard Drive Disk serial number."""
    disk_items = (self._GetDataTypeItems('serialata') +
                  self._GetDataTypeItems('parallelata') +
                  self._GetDataTypeItems('nvme'))
    for disk_item in disk_items:
      for item in disk_item['_items']:
        if 'device_serial' in item:
          self._profile['hdd_serial'] = item['device_serial'].strip()
          return

  def _FindMachineModel(self):
    """Find machine model."""
    for item in self._GetDataTypeItems('hardware'):
      if 'machine_model' in item:
        self._profile['machine_model'] = item['machine_model']
        return

  def _FindPlatformUuid(self):
    """Find platform UUID."""
    for item in self._GetDataTypeItems('hardware'):
      if 'platform_UUID' in item:
        self._profile['platform_uuid'] = item['platform_UUID']
        return

  def _FindSerialNumber(self):
    """Find system serial number."""
    for item in self._GetDataTypeItems('hardware'):
      if 'serial_number' in item:
        self._profile['serial_number'] = item['serial_number']
        return

  def _FindMacAddresses(self):
    """Find MAC addresses for network adapters."""
    for item in self._GetDataTypeItems('network'):
      if 'hardware' in item:
        if 'Ethernet' in item and 'MAC Address' in item['Ethernet']:
          intf_mac = item['Ethernet']['MAC Address']
          intf_name = item.get('interface', None)

          if item['hardware'] == 'Ethernet':
            intf_type = 'ethernet'
          elif item['hardware'] == 'AirPort':
            intf_type = 'airport'
          elif item['hardware'] == 'FireWire':
            intf_type = 'firewire'
          else:
            intf_type = None

          if intf_type is not None:
            self._profile['%s_mac' % intf_type] = intf_mac
            if intf_name is not None:
              self._profile['interface_%s' % intf_name] = intf_type

  def _FindBatteryInfo(self):
    """Find battery info."""
    for item in self._GetDataTypeItems('power'):
      if 'sppower_battery_model_info' in item:
        self._profile['battery_serial_number'] = (
            item['sppower_battery_model_info'].get(
                'sppower_battery_serial_number', 'unknown'))

  def _FindUSBDevices(self):
    """Find all USB devices."""
    for item in self._GetDataTypeItems('usb'):
      if 'host_controller' in item:
        for usb_item in item.get('_items', []):
          if usb_item['_name'].find('iSight') > -1:
            self._profile['isight_serial_number'] = (
                usb_item.get('d_serial_num', 'unknown'))

  def _FindAll(self):
    """Find all properties from system profile."""
    self._GetSystemProfile()
    self._FindHDDSerial()
    self._FindMachineModel()
    self._FindSerialNumber()
    self._FindPlatformUuid()
    self._FindMacAddresses()
    self._FindBatteryInfo()
    self._FindUSBDevices()

  def GetProfile(self):
    """Returns the system profile.

    Returns:
      dict, with some or all these keys = {
        'serial_number': str,
        'platform_uuid': str,
        'ethernet_mac': str,
        'airport_mac': str,
        'firewire_mac': str,
        'hdd_serial': '...',
        'interface_en0': 'ethernet' or 'airport' or 'firewire',
        'interface_enN': ....,
        'interface_fwN': ....,
        'machine_model': str,
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
