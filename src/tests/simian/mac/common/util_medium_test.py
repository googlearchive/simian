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


from google.apputils import app
from google.apputils import basetest
from simian.mac.common import util


class UtilModuleTest(basetest.TestCase):

  def testSerializeNone(self):
    """Test Serialize()."""
    self.assertEqual('null', util.Serialize(None))

  def testSerializeUnicode(self):
    """Test Serialize()."""
    ustr = u'Hello there\u2014'
    ustr_js = '"Hello there\\u2014"'

    # javascript uses the same notation as python to represent unicode
    # characters.
    self.assertEqual(ustr_js, util.Serialize(ustr))

  def testDeserializeUnicode(self):
    """Test Deserialize()."""
    ustr = u'Hello there\u2014'
    ustr_js = '"Hello there\\u2014"'

    self.assertEqual(ustr, util.Deserialize(ustr_js))

  def _DumpStr(self, s):
    """Return any binary string entirely as escaped characters."""
    o = []
    for i in xrange(len(s)):
      o.append('\\x%02x' % ord(s[i]))
    return ''.join(o)

  def testSerializeControlChars(self):
    """Test Serialize()."""
    input = []
    output = []

    for x in xrange(0, 31):
      input.append(chr(x))
      if x == 8:
        output.append('\\b')
      elif x == 9:
        output.append('\\t')
      elif x == 10:
        output.append('\\n')
      elif x == 12:
        output.append('\\f')
      elif x == 13:
        output.append('\\r')
      else:
        output.append('\\u%04x' % x)

    input_str = ''.join(input)
    output_str = '"%s"' % ''.join(output)

    serialized = util.Serialize(input_str)
    self.assertEqual(
        output_str,
        serialized,
        '%s != %s' % (self._DumpStr(output_str), self._DumpStr(serialized)))

  def testSerialize8bitChars(self):
    """Test Serialize()."""
    input = []
    output = []

    for x in xrange(128, 256, 1):
      input.append(chr(x))

    input_str = ''.join(input)

    # the json module does not support encoding arbitrary 8 bit bytes.
    # the bytes wil get snagged up in a unicode utf-8 decode step.
    self.assertRaises(UnicodeDecodeError, util.Serialize, input_str)

  def testSerializeFloat(self):
    """Test Serialize()."""

    # expected behavior: we can only guarentee this level of precision
    # in the unit test because of rounding errors.
    #
    # GAE's float is capable of 10 digits of precision, and a stock
    # python2.6 reports 15 digits from sys.float_info.

    input = {'foo': 103.2261}
    output = '{"foo": 103.2261}'

    self.assertEqual(
        output,
        util.Serialize(input))

  def testDeserializeFloat(self):
    """Test Deserialize()."""
    input = '{"foo": 103.2261}'
    output = {'foo': 103.2261}

    self.assertEqual(
        output,
        util.Deserialize(input))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
