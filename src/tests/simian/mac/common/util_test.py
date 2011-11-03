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

class DatetimeTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.dt = util.Datetime

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testUtcFromTimestampInt(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = util.datetime.datetime(2011, 8, 8, 15, 42, 59)
    epoch = 1312818179
    self.assertEqual(expected_datetime, self.dt.utcfromtimestamp(epoch))

  def testUtcFromTimestampFloat(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = util.datetime.datetime(2011, 8, 8, 15, 42, 59)
    epoch = 1312818179.1415989
    self.assertEqual(expected_datetime, self.dt.utcfromtimestamp(epoch))

  def testUtcFromTimestampString(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = util.datetime.datetime(2011, 8, 8, 15, 42, 59)
    epoch = '1312818179.1415989'
    self.assertEqual(expected_datetime, self.dt.utcfromtimestamp(epoch))

  def testUtcFromTimestampNone(self):
    """Tests utcfromtimestamp() with None as epoch time."""
    self.assertRaises(ValueError, self.dt.utcfromtimestamp, None)

  def testUtcFromTimestampInvalid(self):
    """Tests utcfromtimestamp() with None as epoch time."""
    self.assertRaises(ValueError, self.dt.utcfromtimestamp, 'zz')

  def testUtcFromTimestampUnderOneHourInFuture(self):
    """Tests utcfromtimestamp() with epoch under one hour in the future."""
    epoch = util.time.time() + 600.0  # add ten minutes
    self.assertRaises(
        util.EpochFutureValueError, self.dt.utcfromtimestamp, epoch)

  def testUtcFromTimestampOverOneHourInFuture(self):
    """Tests utcfromtimestamp() with epoch over one hour in the future."""
    epoch = util.time.time() + 4000.0  # add a bit more than 1 hour
    self.assertRaises(
        util.EpochExtremeFutureValueError,
        self.dt.utcfromtimestamp, epoch)


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
    i = socket.htonl(i)
    # on python 2.5 socket.htonl() returns a signed int, on later versions
    # python returns a python long type to return the number without sign.
    if i < 0:
      i = 4294967296L - (long(i) * -1)
    return i

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

  def testSerializePickle(self):
    """Test Serialize()."""
    self.mox.StubOutWithMock(util.pickle, 'dumps')

    util.pickle.dumps('object1').AndReturn('serial1')
    util.pickle.dumps('object2').AndRaise(util.pickle.PicklingError)

    self.mox.ReplayAll()
    self.assertEqual('serial1', util.Serialize(
        'object1', _use_json=False, _use_pickle=True))
    self.assertRaises(
        util.SerializeError,
        util.Serialize,
        'object2', _use_json=False, _use_pickle=True)
    self.mox.VerifyAll()

  def testDeserializePickle(self):
    """Test Deserialize()."""
    self.mox.StubOutWithMock(util.pickle, 'loads')

    util.pickle.loads('serial1').AndReturn('object1')
    util.pickle.loads('serial2').AndRaise(util.pickle.UnpicklingError)

    self.mox.ReplayAll()
    self.assertEqual('object1', util.Deserialize(
        'serial1', _use_json=False, _use_pickle=True,
        _pickle_re=util.re.compile('.')))
    self.assertRaises(
        util.DeserializeError,
        util.Deserialize,
        'serial2', _use_json=False, _use_pickle=True,
        _pickle_re=util.re.compile('.'))
    self.mox.VerifyAll()

  def testSerializeJson(self):
    """Test Serialize()."""
    self.mox.StubOutWithMock(util.json, 'dumps')

    util.json.dumps('object1').AndReturn('serial1')
    util.json.dumps('object2').AndRaise(TypeError)

    self.mox.ReplayAll()
    self.assertEqual('serial1', util.Serialize(
        'object1', _use_json=True, _use_pickle=False))
    self.assertRaises(
        util.SerializeError,
        util.Serialize,
        'object2', _use_json=True, _use_pickle=False)
    self.mox.VerifyAll()

  def testDeserializeJson(self):
    """Test Deserialize()."""
    self.mox.StubOutWithMock(util.json, 'loads')

    util.json.loads('serial1', parse_float=float).AndReturn('object1')
    util.json.loads('serial2', parse_float=float).AndRaise(ValueError)

    self.mox.ReplayAll()
    self.assertEqual('object1', util.Deserialize(
        'serial1', _use_json=True, _use_pickle=False))
    self.assertRaises(
        util.DeserializeError,
        util.Deserialize,
        'serial2', _use_json=True, _use_pickle=False)
    self.mox.VerifyAll()

  def testSerializeNoMethods(self):
    """Test Serialize()."""
    self.mox.ReplayAll()
    self.assertRaises(
        util.SerializeError,
        util.Serialize,
        'object', _use_json=False, _use_pickle=False)
    self.mox.VerifyAll()

  def testDeserializeUnknownFormat(self):
    """Test Deserialize()."""
    self.mox.ReplayAll()
    self.assertRaises(
        util.DeserializeError,
        util.Deserialize,
        'serial', _use_json=False, _use_pickle=False)
    self.mox.VerifyAll()

  def testDeserializeWhenNone(self):
    """Test Deserialize()."""
    self.mox.ReplayAll()
    self.assertRaises(
        util.DeserializeError,
        util.Deserialize,
        None, _use_json=True, _use_pickle=True)
    self.mox.VerifyAll()

  def testPickleDisabled(self):
    """Test that pickle is disabled, per b/3387382."""
    self.assertTrue(util.USE_JSON)
    self.assertFalse(util.USE_PICKLE)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()