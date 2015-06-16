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
#
#

"""IP utility functions."""




def IpToInt(ip):
  """Return a integer for an IP string.

  Output is in network byte order.

  Args:
    ip: str, IP address, like "192.168.0.1"
  Returns:
    int
  Raises:
    ValueError: if IPv6 address is supplied.
  """
  # TODO(user): ipv6 should be supported in the future.
  if ip and ip.find(':') > -1:
    raise ValueError('IPv6')
  ip_int = 0
  a = map(int, ip.split('.'))
  for i in xrange(len(a)):
    ip_int += (a[i] << ((3-i)*8))
  return ip_int


def IpMaskToInts(ip_mask):
  """Transform a network/mask string into integers.

  Output is in network byte order.

  Args:
    ip_mask: str, IP address, like "192.168.0.0/24"
  Returns:
    (int ip, int mask)
  Raises:
    ValueError: if IPv6 address is supplied.
  """
  if ip_mask and ip_mask.find(':') > -1:
    raise ValueError('IPv6')
  (net, mask) = ip_mask.split('/')
  mask = int(mask)
  mask_int = ((2 ** mask) - 1) << (32 - mask)
  return IpToInt(net), mask_int


def IpMaskMatch(ip, ip_mask):
  """Check if an IP is inside an IP mask.

  Args:
    ip: str, like "192.168.0.1"
    ip_mask: str, like "192.168.0.0/24"
  Returns:
    True or False
  Raises:
    ValueError: if IPv6 address is supplied.
  """
  (ip_int_mask, ip_int_mask_bits) = IpMaskToInts(ip_mask)
  ip_int = IpToInt(ip)
  return (ip_int & ip_int_mask_bits) == ip_int_mask
