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
"""util module tests."""

import datetime
import time


import mock
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.common import util


class DatetimeTest(basetest.TestCase):

  def setUp(self):
    self.dt = util.Datetime

  def testUtcFromTimestampInt(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = datetime.datetime(2011, 8, 8, 15, 42, 59)
    epoch = 1312818179
    self.assertEqual(expected_datetime, self.dt.utcfromtimestamp(epoch))

  def testUtcFromTimestampFloat(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = datetime.datetime(2011, 8, 8, 15, 42, 59)
    epoch = 1312818179.1415989
    self.assertEqual(expected_datetime, self.dt.utcfromtimestamp(epoch))

  def testUtcFromTimestampString(self):
    """Tests utcfromtimestamp()."""
    expected_datetime = datetime.datetime(2011, 8, 8, 15, 42, 59)
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
    epoch = time.time() + 600.0  # add ten minutes
    self.assertRaises(
        util.EpochFutureValueError, self.dt.utcfromtimestamp, epoch)

  def testUtcFromTimestampOverOneHourInFuture(self):
    """Tests utcfromtimestamp() with epoch over one hour in the future."""
    epoch = time.time() + 4000.0  # add a bit more than 1 hour
    self.assertRaises(
        util.EpochExtremeFutureValueError,
        self.dt.utcfromtimestamp, epoch)


class UtilModuleTest(basetest.TestCase):

  def testSerializeJson(self):
    """Test Serialize()."""
    with mock.patch.object(util.json, 'dumps', return_value='serial1'):
      self.assertEqual('serial1', util.Serialize('object1'))
    with mock.patch.object(util.json, 'dumps', side_effect=TypeError):
      self.assertRaises(util.SerializeError, util.Serialize, 'object2')

  def testDeserializeJson(self):
    """Test Deserialize()."""
    with mock.patch.object(util.json, 'loads', return_value='object1'):
      self.assertEqual('object1', util.Deserialize('serial1'))
    with mock.patch.object(util.json, 'loads', side_effect=ValueError):
      self.assertRaises(util.DeserializeError, util.Deserialize, 'serial2')

  def testDeserializeWhenNone(self):
    """Test Deserialize()."""
    self.assertRaises(util.DeserializeError, util.Deserialize, None)

  def testUrlUnquote(self):
    """Test UrlUnquote()."""
    self.assertEqual(util.UrlUnquote('foo'), 'foo')
    self.assertEqual(util.UrlUnquote('foo%2F'), 'foo/')
    self.assertEqual(util.UrlUnquote('foo<ohcrap>'), 'foo<ohcrap>')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
