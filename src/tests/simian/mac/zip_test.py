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

"""zip module tests."""




import hashlib
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac import zip


class ZipModuleTest(mox.MoxTestBase):
  """Test the zip module."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class CompressedTextTest(mox.MoxTestBase):
  """Test the CompressedText object."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.decomp_str = 'hello'
    self.decomp_ustr = u'hello\u2019'
    self.comp_str = (
        '%sx\x9c\xcbH\xcd\xc9\xc9\x07\x00\x06,\x02\x15' % zip.MAGIC)
    self.comp_ustr = (
        '%sx\x9c\xcbH\xcd\xc9\xc9\x7f'
        '\xd40\x13\x00\x10\xaa\x04\x10' % zip.MAGIC)

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GetInstance(self, arg=None, compression_threshold=0, **kwargs):
    """Return an instance of zip.CompressedText to test."""
    return zip.CompressedText(
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