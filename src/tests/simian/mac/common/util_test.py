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

"""util module tests."""



from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.common import util

import socket
import struct

class UtilModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _socket_ip2int(self, ip_str):
    """Convert an IP string to int with code other than ours.

    Args:
      ip_str: str
    Returns:
      int in network byte order
    """
    i = struct.unpack('I', socket.inet_aton(ip_str))[0]
    return socket.htonl(i)

  def testIpToInt(self):
    """Test IpToInt()."""
    ip_tests = [
        ['192.168.0.0', 3232235520],
        ['10.0.0.5', 167772165],
    ]

    for ip_str, ip_int_expected in ip_tests:
      self.assertEqual(ip_int_expected, self._socket_ip2int(ip_str))
      self.assertEqual(ip_int_expected, util.IpToInt(ip_str))

  def testIpMaskToInts(self):
    """Test IpMaskToInts()."""
    mask_str = '1.2.3.4/8'
    ip_mask_ints_expected = (
        self._socket_ip2int('1.2.3.4'),
        self._socket_ip2int('255.0.0.0'),
    )
    self.assertEqual(ip_mask_ints_expected, util.IpMaskToInts(mask_str))

  def testIpMaskMatch(self):
    """Test IpMaskMatch()."""
    ip_tests = [
        ['192.168.0.0',   '192.168.0.0/25', True],
        ['192.168.0.127', '192.168.0.0/25', True],
        ['192.168.0.128', '192.168.0.0/25', False],

        ['192.168.0.0',   '192.168.0.0/24', True],
        ['192.168.0.255', '192.168.0.0/24', True],
        ['192.168.0.100', '192.168.1.0/24', False],

        ['192.168.0.0',   '192.168.0.0/23', True],
        ['192.168.1.0',   '192.168.0.0/23', True],
        ['192.168.1.255', '192.168.0.0/23', True],
        ['192.168.2.1',   '192.168.0.0/23', False],

        ['192.168.0.0',   '192.168.0.0/22', True],
        ['192.168.1.0',   '192.168.0.0/22', True],
        ['192.168.1.255', '192.168.0.0/22', True],
        ['192.168.2.255', '192.168.0.0/22', True],
        ['192.168.3.255', '192.168.0.0/22', True],
        ['192.168.4.0',   '192.168.0.0/22', False],

        ['10.0.0.0',       '10.0.0.0/8', True],
        ['10.0.0.1',       '10.0.0.0/8', True],
        ['10.0.1.0',       '10.0.0.0/8', True],
        ['10.1.0.0',       '10.0.0.0/8', True],
        ['10.1.2.3',       '10.0.0.0/8', True],
        ['10.255.255.255', '10.0.0.0/8', True],
        ['11.0.0.0',       '10.0.0.0/8', False],
    ]

    for ip, ip_mask, expected in ip_tests:
      self.assertEqual(
          expected, util.IpMaskMatch(ip, ip_mask),
          '%s %s expected %s' % (ip, ip_mask, expected))

  def testSerialize(self):
    """Test Serialize()."""
    self.mox.StubOutWithMock(util.pickle, 'dumps')

    util.pickle.dumps('object').AndReturn('serial')
    util.pickle.dumps('object').AndRaise(util.pickle.PicklingError)

    self.mox.ReplayAll()
    self.assertEqual('serial', util.Serialize('object'))
    self.assertRaises(util.SerializeError, util.Serialize, 'object')
    self.mox.VerifyAll()
  
  def testDeserialize(self):
    """Test Deserialize()."""
    self.mox.StubOutWithMock(util.pickle, 'loads')

    util.pickle.loads('serial').AndReturn('object')
    util.pickle.loads('serial').AndRaise(util.pickle.UnpicklingError)
    
    self.mox.ReplayAll()
    self.assertEqual('object', util.Deserialize('serial'))
    self.assertRaises(util.DeserializeError, util.Deserialize, 'serial')
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()