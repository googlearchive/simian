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
"""Plist module.

Utility classes to handle Apple .plist files, which are either
  XML docs per
  DTD http://www.apple.com/DTDs/PropertyList-1.0.dtd
OR
  Binary structure per:
  http://www.opensource.apple.com/source/CF/CF-476.10/CFBinaryPList.c
  http://www.opensource.apple.com/source/CF/CF-550/ForFoundationOnly.h
"""

import base64
import datetime
import struct
import xml.parsers.expat
import xml.sax.saxutils

PLIST_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" '
    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    '<plist version="1.0">\n'
    )

PLIST_FOOT = '\n</plist>\n'

PLIST_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# lookup table for valid plist element names
APPLE_PLIST_ELEMENTS = {
    'plist': None,
    'array': None,
    'dict': None,
    'key': None,
    'string': None,
    'integer': None,
    'date': None,
    'false': None,
    'true': None,
    'data': None,
    'real': None,
}


INDENT_CHAR = '  '


PLIST_CONTENT_TYPES = [list, dict, type(None)]


class Error(Exception):
  """Base Exception."""


class PlistError(Error):
  """Plist error."""


class PlistNotParsedError(Error):
  """A plist has not been successfully parsed; called method is unavailable."""


class PlistAlreadyParsedError(Error):
  """A plist has already been parsed from a XML or binary source."""


class MalformedPlistError(PlistError):
  """Malformed Plist, like XML that is not well-formed."""


class InvalidPlistError(PlistError):
  """Invalid Plist, like an XML document that is not valid."""


class BinaryPlistError(PlistError):
  """Base error specific to binary plist format."""


class BinaryPlistHeaderError(BinaryPlistError):
  """The binary header is invalid/malformed/magic is unknown."""


class BinaryPlistVersionError(BinaryPlistError):
  """The binary plist version is unsupported."""


class UTC(datetime.tzinfo):
  """UTC timezone."""

  def utcoffset(self, unused_dt):
    return datetime.timedelta(0)

  def tzname(self, unused_dt):
    return 'UTC'

  def dst(self, unused_dt):
    return datetime.timedelta(0)


class AppleUid(int):
  """Apple UID value, which is an int."""


class AppleData(str):
  """Apple data value, which is a str."""


class ApplePlist(object):
  """Class to read Apple plists and produce a dict.

  To use:
    p = ApplePlist(plist_xml_string)
    p.Parse()
    dictionary = p.Plist()
  """

  # Passed to _ValidateBasic after parsing XML (see docs there).
  _VALIDATE_BASIC_CONFIG = {}

  # struct size strings for various int sizes
  INT_SIZE_FORMAT = {
      1: 'B',
      2: 'H',
      4: 'I',
      8: 'Q',
  }

  # struct size strings for various float sizes
  FLOAT_SIZE_FORMAT = {
      4: 'f',
      8: 'd',
  }

  COUNT_INT_FOLLOWS = 15  # 1111b

  # a binary plist begins with:
  BPLIST_MAGIC = 'bplist'
  BPLIST_VERSIONS = ['00']

  # the OSX CFDateGetAbsoluteTime epoch is 00:00:00 1 January 2001
  EPOCH = datetime.datetime(2001, 1, 1, 0, 0, 0, 0, UTC())

  def __init__(self, plist=None):
    """Initialize the class.

    Args:
      plist: str, optionally supply the Plist on init
    """
    self._validation_hooks = []
    self.Reset()
    if plist is not None:
      self.LoadPlist(plist)

  def copy(self):  # pylint: disable=invalid-name
    """Return a new instance of this plist with the same values."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    # pylint: disable=protected-access
    new_plist = self.__class__()
    new_plist._validation_hooks = self._validation_hooks
    new_plist._plist = self._plist.copy()
    new_plist._plist_xml = self._plist_xml
    new_plist._plist_xml_encoding = self._plist_xml_encoding
    new_plist._plist_bin = self._plist_bin
    new_plist._plist_version = self._plist_version
    new_plist._changed = self._changed
    # pylint: enable=protected-access
    return new_plist

  def LoadPlist(self, plist):
    """Load a plist in binary or XML format.

    Args:
      plist: str, XML or binary plist
    """
    try:
      # try to detect a binary plist, and then load it.
      self._BinLoadHeader(plist)
      self._LoadBinary(plist)
    except BinaryPlistHeaderError:
      # it's not binary, it's likely XML.
      self._LoadDocument(plist)
    except BinaryPlistVersionError:
      # to be consistent, don't raise this exception yet.
      # let it occur on call to Parse().  load the binary plist now.
      self._LoadBinary(plist)

  def _LoadDocument(self, plist_xml):
    """Load but not parse an Apple plist XML document.

    Args:
      plist_xml: str, plist XML
    """
    self.Reset()
    self._plist_xml = plist_xml
    self._plist_bin = None

  def _LoadBinary(self, plist_bin):
    """Load but not parse an Apple binary plist.

    Args:
      plist_bin: str, plist binary
    """
    self.Reset()
    self._plist_bin = plist_bin
    self._plist_xml = None

  def Reset(self):
    """Reset all internal properties to empty."""
    self._changed = False
    self._plist_bin = None
    self._plist_xml = None
    self._plist_xml_encoding = None

    # no _plist property, no plist loaded
    # _plist == None, empty <plist> node contents
    # _plist == other, plist contents
    if hasattr(self, '_plist'):
      del self._plist

    self._plist_version = None
    self._current_mode = []
    self._current_value = []
    self._current_key = []
    self.__bin = {}
    self._type_lookup = {
        0: self._BinLoadSimple,
        1: self._BinLoadInt,
        2: self._BinLoadFloat,
        3: self._BinLoadDate,
        4: self._BinLoadData,
        5: self._BinLoadAsciiStr,
        6: self._BinLoadUnicode,
        7: self._BinLoadUnused,
        8: self._BinLoadUid,
        9: self._BinLoadUnused,
        10: self._BinLoadArray,
        11: self._BinLoadUnused,
        12: self._BinLoadSet,
        13: self._BinLoadDict,
        14: self._BinLoadUnused,
        15: self._BinLoadUnused,
    }

  def _NewMode(self, mode):
    """Push a new mode onto the mode stack, making it current.

    Args:
      mode: str, a mode while scanning the xml, like 'dict', 'data'
    """
    self._current_mode.append(mode)

  def _CurrentMode(self):
    """Return the current mode."""
    return self._current_mode[-1]

  def _ParentMode(self):
    """Return the parent mode."""
    return self._current_mode[-2]

  def _ReleaseMode(self):
    """Release the current mode."""
    self._current_mode.pop(-1)

  def _NewValue(self, value):
    """Push a new value onto the data stack, making it current.

    Args:
      value: any str/int/dict/list
    """
    self._current_value.append(value)

  def _CurrentValue(self):
    """Return the current value."""
    return self._current_value[-1]

  def _ReleaseValue(self):
    """Release the current value."""
    self._current_value.pop(-1)

  def _NewKey(self, key):
    """Push a new key onto the key stack, making it current.

    Args:
      key: str, like 'display_name'
    """
    self._current_key.append(key)

  def _CurrentKey(self):
    """Return the current key.

    Returns:
      str, like 'display_name'
    """
    try:
      return self._current_key[-1]
    except IndexError:
      if self._current_mode[-1] == 'dict':
        # e.g. <string>foo</string> without <key>..</key> before it.
        raise MalformedPlistError('Missing key element before value element')
      else:
        # Undefined error condition, traceback please.
        raise

  def _ReleaseKey(self):
    """Release the current key."""
    self._current_key.pop(-1)

  def _GetParser(self, encoding=None):
    """Return an expat Parser instance.

    Args:
      encoding: str, optional, like 'utf-8'
    Returns:
      xml.parsers.expat.XMLParser instance
    """
    parser = xml.parsers.expat.ParserCreate(encoding)
    parser.StartElementHandler = self._StartElementHandler
    parser.EndElementHandler = self._EndElementHandler
    parser.XmlDeclHandler = self._XmlDeclHandler
    parser.CharacterDataHandler = self._CharacterDataHandler
    return parser

  def _ParseDate(self, date_str):
    """Parse a date string.

    Args:
      date_str: str, in format PLIST_DATE_FORMAT
    Returns:
      datetime with no timezone object, in UTC time
    """
    dt = datetime.datetime.strptime(date_str, PLIST_DATE_FORMAT)
    return dt

  def _ParseData(self, data_str):
    """Parse a data string.

    Args:
      data_str: str, in base64 format
    Returns:
      str, decoded
    """
    return base64.b64decode(data_str)

  def _XmlDeclHandler(self, unused_version, encoding, unused_standalone):
    """Handle the XML declaration header.

    Args:
      unused_version: str, version of XML
      encoding: str, encoding format e.g. 'utf-8'
      unused_standalone: int in [-1, 0, 1], per pyexpat docs
    """
    self._plist_xml_encoding = encoding

  def _StartElementHandler(self, name, attributes):
    """Handle the start of a XML element.

    Args:
      name: str, like "dict"
      attributes: dict, like {'version': '1.0'}, may be empty
    Raises:
      NotImplementedError: if the element name is not recognized
      MalformedPlistError: XML error
    """
    # be careful, avoid invalid XML
    if name not in APPLE_PLIST_ELEMENTS:
      raise MalformedPlistError('Element %s' % name)

    # start of plist node.  initialize.
    if name == 'plist':
      self._NewMode('plist')
      if 'version' in attributes:
        self._plist_version = attributes['version']
      return

    # if the plist node never started yet, fail.
    if self._current_mode[:1] != ['plist']:
      raise MalformedPlistError()

    # start of a key
    if name == 'key':
      self._NewMode(name)
    # start of a dict, put an empty dict on the stack to populate.
    elif name == 'dict':
      self._NewMode(name)
      self._NewValue({})
    # start of an array, put an empty array on the stack to populate.
    elif name == 'array':
      self._NewMode(name)
      self._NewValue([])
    # value is about to arrive, look for it.
    elif name in ['string', 'integer', 'date', 'data', 'real']:
      self._NewMode(name)
    # these elements describe the value also, put it on the stack now.
    elif name in ['true', 'false']:
      self._NewMode(name)
      self._NewMode('value')
      self._NewValue(name == 'true')
    else:
      raise NotImplementedError('XML element %s' % name)

  def _CharacterDataHandler(self, value):
    """Handle CDATA.

    Args:
      value: str
    """
    # ignore newlines and extra junk in between dict and array nodes.
    if self._CurrentMode() in ['dict', 'array']:
      if not value or value == '\n':
        return

    # if looking for values (mode in key,string,integer), then store them
    # from this cdata.
    if self._CurrentMode() == 'key':
      self._NewValue(value)
      self._NewMode('value')
    elif self._CurrentMode() in ['string', 'mvalue']:
      self._NewValue(value)  # put unicode conv logic here if ever needed
      self._NewMode('mvalue')
    elif self._CurrentMode() == 'integer':
      self._NewValue(int(value))
      self._NewMode('value')
    elif self._CurrentMode() == 'date':
      self._NewValue(self._ParseDate(value))
      self._NewMode('value')
    elif self._CurrentMode() == 'data':
      self._NewValue(value)
      self._NewMode('mvalue')
    elif self._CurrentMode() == 'real':
      self._NewValue(float(value))
      self._NewMode('value')

  def _EndElementHandler(self, name):
    """End of an element has occured.

    Args:
      name: str, name of the element, like "dict"
    """
    # if this is the end of the plist element, populate our internal
    # plist property and immediately return.  this completes the XML scan.
    if name == 'plist':
      if self._current_value:
        self._plist = self._CurrentValue()
        self._ReleaseValue()
      else:
        # it's an empty plist, but the plist element did exist.
        self._plist = None
      return

    # if the current mode is value, there is value to be popped off
    # the value stack and stored somewhere that will be determined below.
    if self._CurrentMode() == 'value':
      self._ReleaseMode()
      value = self._CurrentValue()
      self._ReleaseValue()
    # multiple values to be combined together like strings
    elif self._CurrentMode() == 'mvalue':
      value = []
      while self._CurrentMode() == 'mvalue':
        self._ReleaseMode()
        # note: insert at front to reverse order as popped off stack
        value.insert(0, self._CurrentValue())
        self._ReleaseValue()
      value = ''.join(value)
      # if this is a data node, now base64 decode it.
      if self._CurrentMode() == 'data':
        value = self._ParseData(value)
    # if this element ending is an array or dict, we're done building
    # these structures.  pop the value off and keep it to store it.
    elif name in ['array', 'dict']:
      value = self._CurrentValue()
      self._ReleaseValue()
    # this string element is ending, but no value was ever collected
    # so the "_CurrentMode() == value" block above was passed.
    # here, we just provide an empty string as output value instead.
    # e.g. <string></string> == ''
    elif name == 'string':
      value = ''
    else:
      value = None

    # if a key is closing, look for the key value and push it onto
    # the stack.
    if name == 'key':
      if value is None:
        value = ''
      self._NewKey(value)

    # if we are not closing a <key> element, and we are building a dict, a
    # value of the dict is ending here.  that means the earlier <key> value
    # is now useless, pop it off.
    release_key = name != 'key' and self._ParentMode() == 'dict'

    # pop off the current mode and reveal the parent mode to proceed
    self._ReleaseMode()

    # if the mode is now plist, we're almost done. push the entire plist
    # dictionary back in as value and prep it for the final return.
    if self._CurrentMode() == 'plist':
      self._NewValue(value)
      self._NewMode('value')
      return

    # mode is dict or array, we are building these structures.  use the
    # popped value to populate this structure.
    if self._CurrentMode() == 'dict':
      self._CurrentValue()[self._CurrentKey()] = value
    elif self._CurrentMode() == 'array':
      self._CurrentValue().append(value)

    # we finished a key/value pair, pop off the key, it's now not needed.
    if release_key:
      self._ReleaseKey()

  def _BinLoadHeader(self, header=None):
    """Load binary header.

    Args:
      header: str, optional, default internal _plist_bin,
          header to interpret
    Raises:
      BinaryPlistHeaderError: the binary header is malformed
      BinaryPlistVersionError: the binary version is unsupported/unknown
    """
    # chop to exact length of header (see unpack below) to avoid struct.error
    if header is None:
      header = self._plist_bin[0:8]
    else:
      header = header[0:8]

    try:
      (magic, v) = struct.unpack('6s2s', header)
    except struct.error as e:
      raise BinaryPlistHeaderError('Header: %s' % str(e))

    if magic != self.BPLIST_MAGIC:
      raise BinaryPlistHeaderError('Not a plist, wrong magic: %s' % magic)
    if v not in self.BPLIST_VERSIONS:
      raise BinaryPlistVersionError('Unknown plist version: %s' % v)

    self.__bin['magic'] = magic
    self.__bin['v'] = v

  def _BinLoadFooter(self):
    """Load binary footer."""
    fmt = '>5xBBBQQQ'
    try:
      a = struct.unpack(fmt, self._plist_bin[-1 * struct.calcsize(fmt):])
    except struct.error as e:
      raise MalformedPlistError('Footer: %s' % str(e))
    self.__bin['sortVersion'] = a[0]
    self.__bin['offsetIntSize'] = a[1]
    self.__bin['objectRefSize'] = a[2]
    self.__bin['numObjects'] = a[3]
    self.__bin['topObject'] = a[4]
    self.__bin['offsetTableOffset'] = a[5]

  def _BinGetCount(self, ofs):
    """Retrieve a count value at offset.

    The count value is firstly a 4-bit int N, which tells you
    how large the following int is, given following formula:

        Z = 2**N

    Then the remaining int of size Z bytes follow.
    The number of bytes consumed by the count, returned by this method,
    is sometimes necessary for the calling method to step past the int
    and access the next structure (for example dict keyref).

    Args:
      ofs: int, offset in binary
    Returns:
      (number of bytes consumed by count, count value)
    """
    pos = ofs
    l = struct.unpack('>B', self._plist_bin[pos:pos+1])[0] & 0xf
    l = 2 ** l
    c = 0
    pos += 1
    for unused_i in xrange(l):
      c = (c << 8) + ord(self._plist_bin[pos:pos+1])
      pos += 1
    return (pos-ofs, c)

  def _BinLoadSimple(self, unused_ofs, unused_objtype, objarg):
    """Load a binary simple object.

    Args:
      unused_ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      boolean or None
    Raises:
      MalformedPlistError: if the binary structure is broken
    """
    if objarg == 0:
      x = None  # null
    elif objarg == 8:
      x = False
    elif objarg == 9:
      x = True
    elif objarg == 15:
      pass  # fill byte
    else:
      raise MalformedPlistError('Unknown simple %d' % objarg)
    return x

  def _BinLoadDict(self, ofs, unused_objtype, objarg):
    """Load a binary dictionary.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      dict
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg

    if self.__bin['numObjects'] > 255:
      siz = 2
    else:
      siz = 1
    fmt = self.INT_SIZE_FORMAT[siz]

    keyref = struct.unpack('>%d%s' % (c, fmt), self._plist_bin[pos:pos+(siz*c)])
    pos += siz*c
    objref = struct.unpack('>%d%s' % (c, fmt), self._plist_bin[pos:pos+(siz*c)])
    pos += siz*c

    d = {}
    for i in xrange(len(keyref)):
      self._BinLoadObject(self._object_offset[keyref[i]])
      self._BinLoadObject(self._object_offset[objref[i]])
      k = self.__bin[self._object_offset[keyref[i]]]
      v = self.__bin[self._object_offset[objref[i]]]
      d[k] = v
    return d

  def _BinLoadUnused(self, ofs, objtype, objarg):
    """Load unused object.

    (It has no value)

    Args:
      ofs: int, offset in binary
      objtype: int, object type
      objarg: int, object arg
    """
    pass

  def _BinLoadInt(self, ofs, unused_objtype, unused_objarg):
    """Load an integer.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      unused_objarg: int, object arg
    Returns:
      integer
    """
    (unused_l, c) = self._BinGetCount(ofs)
    return c

  def _BinLoadUid(self, ofs, objtype, objarg):
    """Load a uid.

    Args:
      ofs: int, offset in binary
      objtype: int, object type
      objarg: int, object arg
    Returns:
      Uid instance
    """
    return AppleUid(self._BinLoadInt(ofs, objtype, objarg))

  def _BinLoadFloat(self, ofs, unused_objtype, objarg):
    """Load a float.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      float
    """
    pos = ofs + 1
    c = 2**objarg
    fmt = self.FLOAT_SIZE_FORMAT[c]
    f = struct.unpack('>%s' % fmt, self._plist_bin[pos:pos+c])[0]
    return f

  def _BinLoadDate(self, ofs, unused_objtype, unused_objarg):
    """Load a date.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      unused_objarg: int, object arg
    Returns:
      datetime in UTC
    """
    pos = ofs + 1
    f = struct.unpack('>d', self._plist_bin[pos:pos+8])[0]
    td = datetime.timedelta(seconds=f)
    utc_d = self.EPOCH + td
    return utc_d

  def _BinLoadUnicode(self, ofs, unused_objtype, objarg):
    """Load a unicode string.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      unicode str
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg
    c *= 2  # it's actually count of *chars*, not bytes.
    s = unicode(self._plist_bin[pos:pos+c], 'utf-16be')
    pos += c
    return s

  def _BinLoadAsciiStr(self, ofs, unused_objtype, objarg):
    """Load a ascii string.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      str
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg
    s = str(self._plist_bin[pos:pos+c])
    pos += c
    return s

  def _BinLoadArray(self, ofs, unused_objtype, objarg):
    """Load an array.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      list of array contents
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg
    if self.__bin['numObjects'] > 255:
      siz = 2
    else:
      siz = 1
    fmt = self.INT_SIZE_FORMAT[siz]
    objref = struct.unpack(
        '>%d%s' % (c, fmt), self._plist_bin[pos:pos+(siz*c)])

    pos += siz*c

    a = []
    for i in xrange(len(objref)):
      self._BinLoadObject(self._object_offset[objref[i]])
      x = self.__bin[self._object_offset[objref[i]]]
      a.append(x)
    return a

  def _BinLoadSet(self, ofs, unused_objtype, objarg):
    """Load an set.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      set
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg
    if self.__bin['numObjects'] > 255:
      siz = 2
    else:
      siz = 1
    fmt = self.INT_SIZE_FORMAT[siz]
    objref = struct.unpack(
        '>%d%s' % (c, fmt), self._plist_bin[pos:pos+(siz*c)])
    pos += siz*c

    a = set()
    for i in xrange(len(objref)):
      self._BinLoadObject(self._object_offset[objref[i]])
      x = self.__bin[self._object_offset[objref[i]]]
      a.add(x)
    return a

  def _BinLoadData(self, ofs, unused_objtype, objarg):
    """Load arbitrary data.

    Args:
      ofs: int, offset in binary
      unused_objtype: int, object type
      objarg: int, object arg
    Returns:
      str
    """
    pos = ofs + 1
    if objarg == self.COUNT_INT_FOLLOWS:
      (l, c) = self._BinGetCount(pos)
      pos += l
    else:
      c = objarg
    data = self._plist_bin[pos:pos+c]
    pos += c
    return AppleData(data)

  def _BinLoadObject(self, ofs=0):
    """Load an object.

    Args:
      ofs: int, offset in binary
    Returns:
      any value of object (int, str, etc..)
    """
    pos = ofs

    if pos in self.__bin:
      return self.__bin[pos]

    objtype = ord(self._plist_bin[pos]) >> 4
    objarg = ord(self._plist_bin[pos]) & 0xf
    try:
      x = self._type_lookup[objtype](pos, objtype, objarg)
      self.__bin[pos] = x
    except KeyError:
      raise MalformedPlistError('Unknown binary objtype %d' % objtype)
    except (ValueError, TypeError) as e:
      raise MalformedPlistError(
          'Binary struct problem offset %d: %s' % (pos, str(e)))
    return x

  def _BinLoadObjects(self):
    """Load all objects."""
    object_no = self.__bin['topObject']
    objects = self._BinLoadObject(self._object_offset[object_no])
    return objects

  def _BinaryParse(self):
    """Parse a binary plist."""
    self._BinLoadHeader()
    self._BinLoadFooter()
    self._BinLoadOffsetTable()
    self._plist = self._BinLoadObjects()

  def _BinLoadOffsetTable(self):
    """Load binary offset table."""
    ofs = self.__bin['offsetTableOffset']
    int_size = self.__bin['offsetIntSize']
    self._object_offset = {}
    fmt = '>%s' % self.INT_SIZE_FORMAT[int_size]
    for offset_no in xrange(0, self.__bin['numObjects']):
      try:
        oft = struct.unpack(fmt, self._plist_bin[ofs:ofs+int_size])[0]
      except struct.error as e:
        raise MalformedPlistError('Offset table: %s' % str(e))
      self._object_offset[offset_no] = oft
      ofs += int_size

  def Parse(self):
    """Parse a Plist."""
    if hasattr(self, '_plist'):
      raise PlistAlreadyParsedError

    if self._plist_bin:
      self._BinaryParse()
    else:
      parser = self._GetParser()
      try:
        parser.Parse(self._plist_xml)
      except xml.parsers.expat.ExpatError as e:
        raise MalformedPlistError('%s\n\n%s' % (self._plist_xml, str(e)))

    if not hasattr(self, '_plist'):
      raise MalformedPlistError('Plist not parsed; invalid XML?')

    self.Validate()
    self.EncodeXml()

  def AddValidationHook(self, method):
    """Adds a validation hook to run when Validate is called.

    Args:
      method: a callable to execute.
    """
    self._validation_hooks.append(method)

  def _ValidateBasic(self, config):
    """Validate the plist with a config.

    Args:
      config: dict, containing keys to search for, and their expected types.
          e.g.
              { 'key': int,
                'otherkey': str },
    Raises:
      InvalidPlistError: the plist is not valid
    """
    for k in config:
      if k not in self._plist:
        raise InvalidPlistError('Missing element %s' % k)
      if type(self._plist[k]) is not config[k]:
        raise InvalidPlistError(
            'Invalid type for element %s. Got %s, expected %s' % (
                k, type(self._plist[k]), config[k]))

  def Validate(self):
    """Verify that this Plist is valid.

    Raises:
      InvalidPlistError: the plist is not valid
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    for method in self._validation_hooks:
      method()

    if self._VALIDATE_BASIC_CONFIG:
      self._ValidateBasic(self._VALIDATE_BASIC_CONFIG)

  def EncodeXml(self, encoding=None):
    """Encodes the plist xml to a particular encoding.

    Args:
      encoding: str unicode encoding type to use; default None uses encoding
        embedded in XML if present.
    """
    if not encoding:
      encoding = self.GetEncoding()

    if encoding and type(self._plist_xml) is not unicode:
      try:
        self._plist_xml = unicode(self._plist_xml, encoding)
      except LookupError:
        raise InvalidPlistError('Encoding not valid: %s' % encoding)

  def GetContents(self):
    """Return a dictionary or array representing the parsed plist structure.

    Returns:
      contents of plist, typically dictionary or array, or
      None if no contents.
    Raises:
      InvalidPlistError: no parsed plist is available
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError
    return self._plist

  def SetContents(self, plist_obj):
    """Sets an array or dictionary representing plist structure.

    Args:
      plist_obj: array or dictionary plist.
    Raises:
      PlistError: the plist content type is not supported
      other exceptions: as Validate() would raise them
    """
    if type(plist_obj) not in PLIST_CONTENT_TYPES:
      raise PlistError(
          'Plist contents type is not supported: %s' % type(plist_obj))

    self._plist = plist_obj
    self._changed = True
    self._plist_xml = self.GetXml()
    self.Validate()

  def GetEncoding(self):
    """Returns the encoding of the plist document.

    This method lowercases the encoding value in the plist document
    to match the rest of Python.

    Returns:
      str like 'utf-8', not 'UTF-8', or None if encoding is not set.
    """
    if self._plist_xml_encoding:
      return self._plist_xml_encoding.lower()
    return None

  def GetXml(self, indent_num=0, xml_doc=True):
    """Returns string XML document.

    This function will always return a string, even if the plist is invalid,
    empty, or unset.

    Args:
      indent_num: int, number of indents to start from
      xml_doc: bool, True to return a fully fledged xml document including
        xml header and footer, False to return a xml string starting from
        the plist node.
    Returns:
      str
    Raises:
      PlistError: Output of this plist not supported because of its type
    """
    if not hasattr(self, '_plist'):  # no plist is parsed.
      if xml_doc and getattr(self, '_plist_xml', None):
        # A full XML document was requested and unparsed XML is set, return it.
        return self._plist_xml
      elif getattr(self, '_plist_xml', None):
        # Only the XML contents were requested, so parse the unparsed XML, which
        # creates the _plist property for regular use below.
        try:
          self.Parse()
        except PlistError:
          self._plist = None
      else:
        # self._plist_xml is unset or None, so the plist is considered empty.
        self._plist = None

    if type(self._plist) not in PLIST_CONTENT_TYPES:
      raise PlistError(
          'Plist contents type is not supported: %s' % type(self._plist))

    # workaround for empty plists, don't try to decode the None
    # value because of how GetXmlStr() handles them.  at this GetXml()
    # level we know None means NO (0) values, not ONE (1) None value.
    if self._plist is None:
      str_xml = ''
    else:
      # indent +1 from <plist> node if xml_doc
      str_xml = GetXmlStr(self._plist, indent_num=indent_num + (xml_doc * 1))

    if xml_doc:
      return ''.join([PLIST_HEAD, str_xml, PLIST_FOOT])
    else:
      return str_xml

  def GetXmlContent(self, indent_num=0):
    """Returns only the nodes below the plist node of the XML document.

    Args:
      indent_num: int, number of indents to start from
    Returns:
      str or None
    """
    plist_xml = self.GetXml(indent_num=indent_num, xml_doc=False)
    return plist_xml

  def HasChanged(self):
    """Returns true if this plist has been changed since last call.

    Also clears change flag when read.

    Note this change value can be vastly wrong since a simple
    GetContents()['foo']=True will change the internal dictionary but not
    set changed The changed flag is best used strictly in combination with
    Set*() methods in specific uses, or using SetChanged() to set the
    flag when undetectable changes were made.

    Returns:
      bool
    """
    changed = self._changed
    self._changed = False
    return changed

  def SetChanged(self, changed=True):
    """Set changed flag."""
    if type(changed) is bool:
      self._changed = changed
    else:
      raise ValueError('changed must be bool')

  def Equal(self, plist, ignore_keys=None):
    """Checks if a passed plist is the same, ignoring certain keys.

    Args:
      plist: ApplePlist object.
      ignore_keys: optional, sequence, str keys to ignore.
    Returns:
      Boolean. True if the plist is the same, False otherwise.
    Raises:
      PlistNotParsedError: the plist was not parsed.
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if not ignore_keys:
      return self == plist

    for key in plist:
      if key in ignore_keys:
        continue
      try:
        if plist[key] != self._plist[key]:
          return False
      except KeyError:
        return False

    return True

  def __contains__(self, k):
    """Standard python __contains__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    return k in self._plist

  def __getitem__(self, k):
    """Standard python __getitem__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    return self._plist[k]

  def __setitem__(self, k, v):
    """Standard python __setitem__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    self._plist[k] = v
    self._changed = True

  def __delitem__(self, k):
    """Standard python __delitem__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    del self._plist[k]
    self._changed = True

  def __iter__(self):
    """Standard python __iter__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    for i in self._plist:
      yield i

  def __eq__(self, other):
    """Standard python __eq__ method."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    # note: issubclass(classA,classA) is True, too.
    if not issubclass(other.__class__, self.__class__):
      return False
    return self._plist == other.GetContents()

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    """Returns a utf-8 encoded string representation of the plist XML."""
    return self.GetXml().encode('utf-8')

  def __unicode__(self):
    """Returns a unicode representation of the plist XML."""
    return self.GetXml()

  def get(self, k, default=None):  # pylint: disable=g-bad-name
    """Standard python dict get method."""
    if k in self:
      return self[k]
    else:
      return default

  def set(self, k, v):  # pylint: disable=g-bad-name
    """Standard python dict set method."""
    self[k] = v


class MunkiPlist(ApplePlist):
  """Class to read Munki plists and produce a dict."""

  def __init__(self, *args, **kwargs):
    super(MunkiPlist, self).__init__(*args, **kwargs)
    self.AddValidationHook(self._IsPlistEmpty)

  def _IsPlistEmpty(self):
    """Raises InvalidPlistError if plist is empty or non-existent."""
    if not hasattr(self, '_plist') or self._plist is None:
      raise InvalidPlistError


# TODO(user): below plist classes should offer a way to initialize an empty
#             plist with all core/required properties.


class MunkiManifestPlist(MunkiPlist):
  """Munki Manifest plist."""

  # TODO(user): allow verification of existence of one of the supported
  #   install types, but not forcing any single one; i.e. managed_installs or
  #   managed_uninstalls or managed_updates.
  _VALIDATE_BASIC_CONFIG = {
      'catalogs': list,
  }


class MunkiPackageInfoPlist(MunkiPlist):
  """Munki PackageInfo plist."""

  _VALIDATE_BASIC_CONFIG = {
      'catalogs': list,
      'installer_item_location': unicode,
      'installer_item_hash': unicode,
      'name': unicode,
  }

  def __init__(self, *args, **kwargs):
    super(MunkiPackageInfoPlist, self).__init__(*args, **kwargs)
    self.AddValidationHook(self._ValidateForceInstallAfterDate)
    self.AddValidationHook(self._ValidateInstallerItemLocation)
    self.AddValidationHook(self._ValidateInstallsFilePath)
    self.AddValidationHook(self._ValidateName)

  def _ValidateForceInstallAfterDate(self):
    """Validate the force_install_after_date field, ensuring it's a date.

    Raises:
      InvalidPlistError: the plist is not valid.
      PlistNotParsedError: the plist was not parsed.
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if 'force_install_after_date' in self._plist:
      if not isinstance(
          self._plist['force_install_after_date'], datetime.datetime):
        raise InvalidPlistError(
            'force_install_after_date must be a date, received a %r' % (
                type(self._plist['force_install_after_date'])))

  def _ValidateInstallerItemLocation(self):
    """Validate a pkginfo <key>installer_item_location</key> value."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if self._plist.get('installer_item_location', '').find('/') != -1:
      raise InvalidPlistError(
          '<key>installer_item_location</key> cannot contain paths: %s' % (
              self._plist['installer_item_location']))

  def _ValidateInstallsFilePath(self):
    """Validate the path strings of installs node of type=file.

    Raises:
      InvalidPlistError: the plist is not valid.
      PlistNotParsedError: the plist was not parsed.
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if 'installs' in self._plist:
      if not isinstance(self._plist['installs'], list):
        raise InvalidPlistError('installs must be an array.')
      for install in self._plist['installs']:
        if install.get('type') == 'file':
          if install.get('path'):
            if install['path'].find('\n') > -1:
              raise InvalidPlistError(
                  'Illegal newlines in install path', install)
          else:
            raise InvalidPlistError(
                'Missing path value for installs type file')

  def _ValidateName(self):
    """Validate a pkginfo <key>name</key> value."""
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    # verify the pkginfo "name" field does not contain any dashes, as they
    # conflict with Munki's manifest <pkginfo_name>-<version> selection feature.
    if self._plist.get('name', '').find('-') != -1:
      raise InvalidPlistError(
          '<key>name</key> cannot contain a dash: %s' % self._plist['name'])

  def GetPackageName(self):
    """Returns the name of the package in the pkginfo plist.

    Returns:
      String name of package from plist.
    Raises:
      PlistError: name attribute was not in the plist.
      PlistNotParsedError: the plist was not parsed.
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if 'name' in self._plist:
      return self._plist['name']
    else:
      raise PlistError('Package name not found in pkginfo plist.')

  def GetMunkiName(self):
    """Construct and return the munki pkg-ver name.

    Returns:
      str munki name like "FooPkg-1.2.3.
    Raises:
      PlistNotParsedError: the plist was not parsed.
      InvalidPlistError: pkginfo is missing required fields; version is always
        requires, and either display_name or name are required.
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if 'version' not in self._plist:
      raise InvalidPlistError('pkginfo is missing version key')

    if 'display_name' in self._plist:
      return '%s-%s' % (self._plist['display_name'], self._plist['version'])
    else:
      if 'name' not in self._plist:
        raise InvalidPlistError('pkginfo is missing name and display_name keys')
      return '%s-%s' % (self._plist['name'], self._plist['version'])

  def SetDescription(self, description):
    """Set the package info description.

    Args:
      description: str, description
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    self._plist['description'] = description
    self._changed = True

  def SetDisplayName(self, display_name):
    """Set the package info display name.

    Args:
      display_name: str, display name
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    self._plist['display_name'] = display_name
    self._changed = True

  def SetUnattendedInstall(self, unattended_install):
    """Set the package info unattended install.

    Args:
      unattended_install: bool, unattended install?
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if unattended_install:
      self._plist['unattended_install'] = True
      # TODO(user): remove backwards compatibility at some point...
      self._plist['forced_install'] = True
      self._changed = True
    else:
      if 'unattended_install' in self._plist:
        del self._plist['unattended_install']
        self._changed = True
      # TODO(user): remove backwards compatibility at some point...
      if 'forced_install' in self._plist:
        del self._plist['forced_install']
        self._changed = True

  def SetUnattendedUninstall(self, unattended_uninstall):
    """Set the package info unattended uninstall.

    Args:
      unattended_uninstall: bool, unattended uninstall?
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    if unattended_uninstall:
      self._plist['unattended_uninstall'] = True
      # TODO(user): remove backwards compatibility at some point...
      self._plist['forced_uninstall'] = True
      self._changed = True
    else:
      if 'unattended_uninstall' in self._plist:
        del self._plist['unattended_uninstall']
        self._changed = True
      # TODO(user): remove backwards compatibility at some point...
      if 'forced_uninstall' in self._plist:
        del self._plist['forced_uninstall']
        self._changed = True

  def SetCatalogs(self, catalogs):
    """Set the package info catalogs.

    Args:
      catalogs: list, catalogs
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    self._plist['catalogs'] = catalogs
    self._changed = True

  def RemoveDisplayName(self):
    """Removes the display_name key from the plist."""
    if 'display_name' in self._plist:
      del self._plist['display_name']

  def EqualIgnoringManifestsAndCatalogs(self, pkginfo):
    """Returns True if the pkginfo is equal except the manifests."""
    return self.Equal(pkginfo, ignore_keys=['manifests', 'catalogs'])


class AppleSoftwareCatalogPlist(ApplePlist):
  """Apple software catalog."""

  def SetCatalogs(self, catalogs):
    """Set the package info catalogs.

    Args:
      catalogs: list, catalogs
    Raises:
      PlistNotParsedError: the plist was not parsed
    """
    if not hasattr(self, '_plist'):
      raise PlistNotParsedError

    self._plist['catalogs'] = catalogs
    self._changed = True


def EscapeString(s):
  """Given a string, return a XML-escaped version.

  Args:
    s: str
  Returns:
    str
  """
  return xml.sax.saxutils.escape(s)


def DictToXml(xml_dict, indent_num=None):
  """Returns string XML of all items in a sequence or nested sequences.

  Args:
    xml_dict: dict to convert to XML.
    indent_num: optional integer; how many times to indent output.
  Returns:
    String XML.
  """
  if indent_num is None:
    indent_num = 0
  indent = INDENT_CHAR * indent_num
  child_indent = INDENT_CHAR * (indent_num + 1)
  str_xml = []
  str_xml.append('%s<dict>' % indent)

  for key in sorted(xml_dict):
    value = xml_dict[key]
    str_xml.append('%s<key>%s</key>' % (child_indent, EscapeString(key)))
    str_xml.append(GetXmlStr(value, indent_num=indent_num + 1))
  str_xml.append('%s</dict>' % indent)
  return '\n'.join(str_xml)


def SequenceToXml(sequence, indent_num=None):
  """Returns string XML of all items in a sequence or nested sequences.

  Args:
    sequence: list or tuple to convert to XML.
    indent_num: optional integer; how many times to indent output.
  Returns:
    String XML.
  """
  if indent_num is None:
    indent_num = 0
  indent = INDENT_CHAR * indent_num
  str_xml = []
  str_xml.append('%s<array>' % indent)
  for value in sequence:
    str_xml.append(GetXmlStr(value, indent_num=indent_num + 1))
  str_xml.append('%s</array>' % indent)
  return '\n'.join(str_xml)


def GetXmlStr(value, indent_num=None):
  """Returns XML representation of a variable.

  Args:
    value: any supported type: list, tuple, dict, str, unicode, int.
    indent_num: optional integer; how many times to indent output.
  Returns:
    String XML.
  Raises:
    PlistError: a plist type is not supported in output
  """
  # TODO(user): refactor and write unit tests.
  if indent_num is None:
    indent_num = 0
  indent = INDENT_CHAR * indent_num
  str_xml = []
  value_type = type(value)
  if value_type is list or value_type is tuple:
    str_xml.append(SequenceToXml(value, indent_num=indent_num))
  elif value_type is dict:
    str_xml.append(DictToXml(value, indent_num=indent_num))
  elif value_type is str or value_type is unicode:
    str_xml.append('%s<string>%s</string>' % (indent, EscapeString(value)))
  elif value_type is int:
    str_xml.append('%s<integer>%d</integer>' % (indent, value))
  elif value_type is float:
    str_xml.append('%s<real>%f</real>' % (indent, value))
  elif value_type is bool:
    if value:
      str_xml.append('%s<true/>' % indent)
    else:
      str_xml.append('%s<false/>' % indent)
  elif value_type is datetime.datetime:
    date_str = value.strftime(PLIST_DATE_FORMAT)
    str_xml.append('%s<date>%s</date>' % (indent, date_str))
  elif value_type is type(None):
    # NOTE(user):  This is not the defined behavior if we use plutil(1)
    # as a reference.  plutil is unwilling to convert binary plists
    # with null type values into XML.
    str_xml.append('%s<string></string>' % indent)
  elif value.__class__ is AppleUid:
    str_xml.append(
        '%s<dict><key>CF$UID</key><integer>%s</integer></dict>' % (
            indent, value))
  elif value.__class__ is AppleData:
    str_xml.append('%s<data>%s</data>' % (indent, base64.b64encode(value)))
  elif issubclass(value.__class__, ApplePlist):
    str_xml.append(value.GetXmlContent(indent_num=indent_num))
  else:
    raise PlistError('Value type %s not supported: %s', value_type, value)
  return '\n'.join(str_xml)


def UpdateIterable(o, ki, value=None, default=None, op=None):
  """Update iteratable object 'o' at [Key or Index].

  Args:
    o: iterable object like list or dict
    ki: key/index position to update
    value: if defined, value to set at key/index
    default: if defined, value to set if key/index does not yet exist,
      otherwise no initialization is performed and operations on
      non-existent keys or indexes raise KeyError/IndexError
    op: if defined, a function to call with args (o[ki], value).
      if the function returns a value other than None, that value
      is used to update o[ki].  if None is returned, it is assumed
      that the op function did something with the value and no further
      operation is needed.
  Returns:
    None
  Raises:
    KeyError: if performing an op on a non-existent key without
      default parameter used
    IndexError: if performing an op on a non-existent or non-consecutive
      index without default parameter used
  """
  if default is not None and ki not in o:
    o[ki] = default

  if op is not None:
    new_v = op(o[ki], value)
    if new_v is not None:
      value = new_v
    else:
      value = None

  if value is not None:
    o[ki] = value
