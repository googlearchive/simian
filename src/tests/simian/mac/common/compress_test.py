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
"""compress module tests."""

import hashlib

import mock
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac.common import compress


class CompressedTextTest(basetest.TestCase):
  """Test the CompressedText object."""

  def setUp(self):
    self.decomp_str = 'hello'
    self.decomp_ustr = u'hello\u2019'
    self.comp_str = (
        '%sx\x9c\xcbH\xcd\xc9\xc9\x07\x00\x06,\x02\x15' % compress.MAGIC)
    self.comp_ustr = (
        '%sx\x9c\xcbH\xcd\xc9\xc9\x7f'
        '\xd40\x13\x00\x10\xaa\x04\x10' % compress.MAGIC)

  def _GetInstance(self, arg=None, compression_threshold=0, **kwargs):
    """Return an instance of compress.CompressedText to test."""
    return compress.CompressedText(
        arg=arg, compression_threshold=compression_threshold, **kwargs)

  def testIsCompressed(self):
    """Test _IsCompressed()."""
    ct = self._GetInstance()
    self.assertTrue(ct._IsCompressed('%shello' % ct.MAGIC))
    self.assertFalse(ct._IsCompressed('hello'))

  def testCompress(self):
    """Test _Compress()."""
    input_data = self.decomp_str
    output_data = self.comp_str

    ct = self._GetInstance(compression_threshold=len(input_data)*2)

    # too little data, pass through
    self.assertEqual(
        ct._Compress(input_data),
        input_data)

    # already encrypted, pass through
    self.assertEqual(
        ct._Compress(output_data),
        output_data)

    ct.COMPRESSION_THRESHOLD = 0

    # enough data and not already encrypted
    self.assertEqual(
        ct._Compress(input_data),
        output_data)

  def testDecompress(self):
    """Test _Decompress()."""
    input_data = self.comp_str
    output_data = self.decomp_str

    ct = self._GetInstance()

    self.assertEqual(
        ct._decompress(input_data),
        output_data)

    self.assertEqual(
        ct._decompress(output_data),
        output_data)

  def testUpdateWithInvalidUtf8Input(self):
    """Test Update() with invalid utf-8 chars input."""

    # Reference below for raw byte encoding of REPLACE char:
    # http://www.fileformat.info/info/unicode/char/fffd/index.htm
    arg = 'Foo\xb0\x01\x01 Bar'
    new_arg = 'Foo\xef\xbf\xbd\x01\x01 Bar'

    ct = self._GetInstance()

    with mock.patch.object(
        ct, '_Compress', return_value='compressed_arg') as mock_compress:
      with mock.patch.object(ct, '_IsCompressed', return_value=False):
        ct.Update(arg, encoding='utf-8')
        self.assertEqual(ct._value, 'compressed_arg')

      mock_compress.assert_called_once_with(new_arg)

  def testCompressed(self):
    """Test Compressed()."""
    input_data = self.decomp_str
    output_data = self.comp_str
    ct = self._GetInstance(input_data, compression_threshold=0)
    self.assertEqual(ct.Compressed(), output_data)

  def testStr(self):
    """Test __str__()."""
    input_data = self.decomp_str
    ct = self._GetInstance(input_data, compression_threshold=0)
    cs = str(ct)
    self.assertEqual(cs, self.decomp_str)
    self.assertEqual(unicode(ct), unicode(self.decomp_str))
    self.assertTrue(type(cs) is type(input_data))

  def testUnicode(self):
    """Test init and output with unicode object."""
    input_data = self.decomp_ustr
    ct = self._GetInstance(input_data, compression_threshold=0)
    cs = unicode(ct)
    self.assertEqual(cs, input_data)
    self.assertTrue(type(cs) is type(input_data))

  def testUnicodeEncoded(self):
    """Test init and output with encoded str that contains unicode chars."""
    input_data = self.decomp_ustr
    input_data_enc = self.decomp_ustr.encode('utf-16be')

    ct = self._GetInstance(input_data_enc, encoding='utf-16be')
    cs = str(ct)
    cu = unicode(ct)

    self.assertEqual(cs, input_data_enc)
    self.assertEqual(cu, input_data)
    self.assertTrue(type(cs) is type(input_data_enc))
    self.assertTrue(type(cu) is type(input_data))

  def testRepr(self):
    """Test __repr__()."""
    input_data = self.decomp_str
    output_data = self.comp_str
    ct = self._GetInstance(input_data, compression_threshold=0)
    hash = hashlib.sha256()
    hash.update(input_data)
    hash = hash.hexdigest()
    input_bytes = len(input_data)
    compressed_bytes = len(output_data)
    r = 'CompressedText(%s %db->%db, %s)' % (
        hash, input_bytes, compressed_bytes, 'None')
    self.assertEqual(r, repr(ct))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
