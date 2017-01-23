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
"""Module for a container class of zlib-encoded text."""

import hashlib
import zlib


MAGIC = '!@#zlib'
MAGIC_LEN = len(MAGIC)
INTERNAL_ENCODING = 'utf-8'
COMPRESSION_THRESHOLD = 665600  # 650K


class CompressedText(object):
  """Container for compressed text.

  Compressed format is:

  MAGIC + ZLIB COMPRESSED OUTPUT

  But only if len(text) > COMPRESSION_THRESHOLD
  """

  def __init__(
      self, arg=None,
      encoding=None, compression_threshold=COMPRESSION_THRESHOLD):
    self.MAGIC = MAGIC
    self.MAGIC_LEN = MAGIC_LEN
    self.INTERNAL_ENCODING = INTERNAL_ENCODING
    self.COMPRESSION_THRESHOLD = compression_threshold

    if arg is None:
      arg = ''
    self.Update(arg, encoding)

  def _IsCompressed(self, data):
    """Returns true if data is already compressed."""
    return data.startswith(self.MAGIC)

  def _Compress(self, data):
    """Returns MAGIC + zlib compressed output for data.

    If data is already compressed, returns it in a compressed form
    which may be of the same form, identical bytes, and same exact variable.

    If data is fewer bytes than COMPRESSION_THRESHOLD, returns the data
    variable unchanged.

    Args:
      data: str, data to compress
    Returns:
      str of compressed data
    """
    if self._IsCompressed(data) or len(data) < self.COMPRESSION_THRESHOLD:
      return data
    else:
      return '%s%s' % (self.MAGIC, zlib.compress(data))

  def _decompress(self, data):
    """Returns data for MAGIC + zlib compressed input.

    If data is not compressed, returns the data unchanged.

    Args:
      data: str, data to decompress
    Returns:
      str of decompressed data
    """
    if self._IsCompressed(data):
      return zlib.decompress(data[self.MAGIC_LEN:])
    else:
      return data

  def Update(self, arg, encoding=None):
    """Update the internal value and encoding.

    Args:
      arg: str or unicode, may be compressed or decompressed
      encoding: str or None, encoding type for str arg
    """
    self._encoding = encoding

    if not self._IsCompressed(arg):
      if encoding is not None:
        arg = arg.decode(encoding, 'replace')
      arg = arg.encode(self.INTERNAL_ENCODING)
    # still pass the value through _Compress() which is expected to
    # tolerate compressed or uncompressed data and do the right thing.
    arg = self._Compress(arg)
    self._value = arg

  def Compressed(self):
    """Returns the compressed form of the text."""
    return self._value

  def __str__(self):
    """Returns the uncompressed form of the text as a str."""
    s = self._decompress(self._value)
    s = s.decode(self.INTERNAL_ENCODING)
    # return the encoding to that of the original input encoding.
    if self._encoding is not None:
      s = s.encode(self._encoding)
    return s

  def __unicode__(self):
    """Returns the uncompressed form of the text as a unicode."""
    s = self._decompress(self._value)
    s = s.decode(self.INTERNAL_ENCODING)
    return s

  def __repr__(self):
    """Returns string roughly representing this instances content."""
    s = str(self)         # note that this decompresses to get the length
    input_bytes = len(s)
    hash_obj = hashlib.sha256()
    hash_obj.update(s)
    hash_obj = hash_obj.hexdigest()
    compressed_bytes = len(self.Compressed())
    r = 'CompressedText(%s %db->%db, %s)' % (
        hash_obj, input_bytes, compressed_bytes, self._encoding)
    return r
