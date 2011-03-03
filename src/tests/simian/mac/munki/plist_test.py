#!/usr/bin/env python
# 
# Copyright 2010 Google Inc. All Rights Reserved.
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

"""plist module tests."""



import base64
import datetime
import pprint
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.munki import plist


class PlistModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testUpdateIterable(self):
    """Test UpdateIterable()."""
    d = {
      'foo': [0, 1],
    }

    array_add = lambda a, v: a.append(v)
    dict_add = lambda d, v: d.update(v)

    plist.UpdateIterable(d, 'foo', 2, default=[], op=array_add)
    self.assertEqual(d['foo'], [0, 1, 2])

    plist.UpdateIterable(d, 'simple', 'hello')
    self.assertEqual(d['simple'], 'hello')

    plist.UpdateIterable(d, 'simple', 'hello', op=lambda d, v: v.upper())
    self.assertEqual(d['simple'], 'HELLO')

    plist.UpdateIterable(d, 'newd', default={})
    self.assertEqual(d['newd'], {})

    plist.UpdateIterable(d, 'newd', {'newv':1}, op=dict_add)
    self.assertEqual(
        d,
        {
          'foo': [0, 1, 2],
          'simple': 'HELLO',
          'newd': {'newv': 1},
        },
    )


class ApplePlistTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.apl = plist.ApplePlist()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def assertPlistEquals(self, plist_dict):
    """Higher level assert for Plist equality testing.

    Args:
      plist_dict: dict, expected dictionary output from Plist()
    """
    failure_str = '\n\nPlist output = \n%s\n\n!= Expected dictionary\n%s' % (
        pprint.pformat(self.apl.GetContents()),
        pprint.pformat(plist_dict),
        )
    self.assertEquals(self.apl.GetContents(), plist_dict, failure_str)

  def testParseDate(self):
    """Test _ParseDate()."""
    mock_dt = 'dt'
    date_str = '12345'
    self.stubs.Set(
        plist.datetime, 'datetime',
        self.mox.CreateMock(plist.datetime.datetime))
    plist.datetime.datetime.strptime(
        date_str, plist.PLIST_DATE_FORMAT).AndReturn(mock_dt)

    self.mox.ReplayAll()
    self.assertEqual(self.apl._ParseDate(date_str), mock_dt)
    self.mox.VerifyAll()

  def testParseData(self):
    """Test _ParseData()."""
    mock_data = 'decoded data'
    data_str = 'b64 encoded data'
    self.mox.StubOutWithMock(plist.base64, 'b64decode')
    plist.base64.b64decode(data_str).AndReturn(mock_data)

    self.mox.ReplayAll()
    self.assertEqual(self.apl._ParseData(data_str), mock_data)
    self.mox.VerifyAll()

  def testValidateBasic(self):
    """Test _ValidateBasic."""
    self.apl._plist = { 'findthis': 12345 }
    config = { 'findthis': int }
    self.apl._ValidateBasic(config)

    self.apl._plist = { 'findthis': 'evil string' }
    self.assertRaises(
        plist.InvalidPlistError, self.apl._ValidateBasic, config)

    self.apl._plist = { 'unknown': 1 }
    self.assertRaises(
        plist.InvalidPlistError, self.apl._ValidateBasic, config)

  def testValidateInvalidPlists(self):
    """Test Validate() with None and empty plists."""
    self.apl._plist = None
    self.assertRaises(plist.PlistNotParsedError, self.apl.Validate)
    self.apl._plist = {}
    self.assertRaises(plist.InvalidPlistError, self.apl.Validate)

  def testValidateSuccessWithAddedHook(self):
    """Test Validate() with a success."""
    self.apl._VALIDATE_BASIC_CONFIG = {'not empty': True}
    self.mox.StubOutWithMock(
        self.apl, '_ValidateBasic', self.mox.CreateMockAnything())
    self.apl._ValidateBasic(self.apl._VALIDATE_BASIC_CONFIG).AndReturn(None)
    self.apl._plist = {'something': 1}
    self.apl.ValidateFoo = self.mox.CreateMockAnything()
    self.apl.ValidateFoo().AndReturn(None)
    self.apl.AddValidationHook(self.apl.ValidateFoo)
    self.mox.ReplayAll()
    self.apl.Validate()
    self.mox.VerifyAll()

  def testEncodeXMLError(self):
    """Test Validate() with invalid/unknown encoding."""
    self.apl._plist_xml = 'crazy encoded string'
    self.mox.StubOutWithMock(
        self.apl, 'GetEncoding', self.mox.CreateMockAnything())
    self.apl.GetEncoding().AndReturn('INVALID ENCODING!!!')
    self.mox.ReplayAll()
    self.assertRaises(plist.InvalidPlistError, self.apl.EncodeXML)
    self.mox.VerifyAll()

  def testGetContents(self):
    """Test GetContents()."""
    self.apl._plist = None
    self.assertRaises(plist.PlistNotParsedError, self.apl.GetContents)
    self.apl._plist = {}
    self.assertEqual({}, self.apl.GetContents())

  def PlistTest(self, plist_xml, plist_dict=None, exc=None):
    """Test invoking Parse().

    Args:
      plist_xml: str, XML document
      plist_dict: dict, optional, expected dictionary output from Plist
      exc: Exception, optional, expected exception when calling Parse()
    """
    self.apl.LoadDocument(plist_xml)
    if exc is not None:
      self.assertRaises(exc, self.apl.Parse)
      self.assertEqual(self.apl._plist, None)
    else:
      self.apl.Parse()
      self.assertPlistEquals(plist_dict)

  def _testBasicEmpty(self):
    """Test a basic plist doc."""
    self.apl.LoadDocument('<plist version="1.0">\n\n  </plist>')
    self.assertRaises(plist.InvalidPlistError, self.apl.Parse)
    self.apl._plist = {}
    self.assertEqual(None, self.apl.GetXml())
    self.assertEqual(None, self.apl.GetXmlContent())
    self.assertEqual(None, self.apl.GetEncoding())

  def testBasicBroken(self):
    """Test a basic broken plist doc."""
    self.PlistTest(
        '<key>omg</key>',
        exc=plist.MalformedPlistError
        )

  def testBasic(self):
    """Test with a plist that should parse OK."""
    xml = ('%s  <dict>\n    <key>foo</key>\n    <string>bar</string>\n  '
           '</dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    self.PlistTest(xml, {'foo': 'bar'})
    self.assertEqual(xml, self.apl.GetXml())
    self.assertEqual(self.apl.GetEncoding(), 'utf-8')
    self.assertEqual(
        '<dict>\n  <key>foo</key>\n  <string>bar</string>\n</dict>',
        self.apl.GetXmlContent())

  def testBasicData(self):
    xml = ('%s  <dict>\n    <key>foo</key>\n    '
           '<data>aGVsbG8gdGhlcmU=</data>\n  '
           '</dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    self.PlistTest(xml, {'foo': 'hello there'})

  def testBasicDataEmptyKey(self):
    xml = ('%s  <dict>\n    <key></key>\n    '
           '<data>d2hhdCBhIGJ1ZyB0aGlzIHdhcw==</data>\n  '
           '</dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    self.PlistTest(xml, {'': 'what a bug this was'})

  def testBasicNested(self):
    xml = ('%s  <dict>\n    <key>foo</key>\n    <string>bar</string>\n  '
           '</dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    xml2 = ('%s  <dict>\n    <key>subway</key>\n    <string>BDFM</string>\n  '
           '</dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    nested_xml = ('%s  <dict>\n    <key>foo</key>\n    <dict>\n'
                  '      <key>subway</key>\n'
                  '      <string>BDFM</string>\n'
                  '    </dict>\n'
                  '  </dict>%s' % (plist.PLIST_HEAD, plist.PLIST_FOOT))
    plist2 = plist.ApplePlist(xml2)
    plist2.Parse()
    self.PlistTest(xml, {'foo': 'bar'})
    self.apl.GetContents()['foo'] = plist2
    self.assertEqual(nested_xml, self.apl.GetXml())

  def testDictToXml(self):
    """Test DictToXml().

    Tests integers, strings, booleans, None, as well as nested dicts/arrays.
    """
    d = {'foo': [1, 'two', [False]], 'bar': {'foobar': None}, 'outside': True}
    out = ('<dict>\n  <key>outside</key>\n  <true/>\n  '
           '<key>foo</key>\n  <array>\n    <integer>1</integer>\n    '
           '<string>two</string>\n    <array>\n      <false/>\n    </array>\n  '
           '</array>\n  <key>bar</key>\n  <dict>\n    <key>foobar</key>\n    '
           '<string></string>\n  </dict>\n</dict>')
    self.assertEquals(out, plist.DictToXml(d, indent_num=0))

  def testSequenceToXml(self):
    """Test SequenceToXml()."""
    seq = [[1, 2, 3], 4, 5, 6]
    out = ('<array>\n  <array>\n    <integer>1</integer>\n    '
           '<integer>2</integer>\n    <integer>3</integer>\n  </array>\n  '
           '<integer>4</integer>\n  <integer>5</integer>\n  '
           '<integer>6</integer>\n</array>')
    self.assertEquals(out, plist.SequenceToXml(seq, indent_num=0))

  def testSequenceToXmlWhenAppleUid(self):
    """Test SequenceToXml()."""
    seq = [plist.AppleUid(999)]
    out = ('<array>\n  <dict>'
           '<key>CF$UID</key><integer>999</integer></dict>\n</array>')
    self.assertEquals(out, plist.SequenceToXml(seq, indent_num=0))

  def testSequenceToXmlWhenAppleData(self):
    seq = [plist.AppleData('hello')]
    out = '<array>\n  <data>aGVsbG8=</data>\n</array>'
    self.assertEquals(out, plist.SequenceToXml(seq, indent_num=0))

  def testBinaryInvalid(self):
    """Test with a broken binary plist."""
    plist_bin = "bplist00\x00\x00\x00otherstuff"
    self.PlistTest(plist_bin, exc=plist.MalformedPlistError)

  def testBinaryInvalidVersion(self):
    """Test with a broken binary plist that has a weird version."""
    plist_bin = "bplist01\x00\x00hello"
    self.PlistTest(plist_bin, exc=plist.BinaryPlistVersionError)

  def testBinaryInvalidSlightly(self):
    """Test with a broken binary plist."""
    plist_bin = base64.b64decode("""
YnBsaXN0MDDYAQIDBAUGBwgJCgsMDQ4PEFNYgjWK+lgulSlZJWlzUGlXaXNGYWxzZVZpc0RhdGFT
Zm9vV2lzVG9kYXlXaXNBcnJheRAJCSJASPXDCEQBAgP/U2JhcjNBtGtLgAAAAKMREhNRMVEyUTMI
GR0kKTE4PERMTk9UVVpeZ2ttbwAAAAAAAAEBAAAAAAAAABQAAAAAAAAAAAAAAAAAAABx""")
    self.PlistTest(plist_bin, exc=plist.MalformedPlistError)

  def testBinary(self):
    """Test with a binary plist."""
    plist_bin = base64.b64decode("""
YnBsaXN0MDDYAQIDBAUGBwgJCgsMDQ4PEFNpczlWaXNUcnVlVGlzUGlXaXNGYWxzZVZpc0RhdGFT
Zm9vV2lzVG9kYXlXaXNBcnJheRAJCSJASPXDCEQBAgP/U2JhcjNBtGtLgAAAAKMREhNRMVEyUTMI
GR0kKTE4PERMTk9UVVpeZ2ttbwAAAAAAAAEBAAAAAAAAABQAAAAAAAAAAAAAAAAAAABx""")
    plist_dict = {
      'foo': 'bar',
      'is9': 9,
      'isArray': ['1', '2', '3'],
      'isData': plist.AppleData('\x01\x02\x03\xff'),
      'isFalse': False,
      'isTrue': True,
      'isPi': 3.1400001049041748,
      'isToday': datetime.datetime(2011, 11, 10, 0, 0, tzinfo=plist.UTC()),
    }
    self.PlistTest(plist_bin, plist_dict)

  def testBinaryNoneAndUid(self):
    """Test with a binary plist.

    Note this test data includes a "null" value, which we translate
    into "None" in Python.

    Note also that expected isTrue is None in plist_dict.  This is
    intentional.  In the process of creating test data for this unit test
    with OSX defaults(1), I used a boolean data container for "isNone", set
    it to True, and then hexedited it to becoming a null value.  (See the
    structure relationship in _BinLoadSimple to see why).  Unfortunately
    defaults had tried to save space and assigned isTrue and isNone to
    the same value container, so isTrue also became None when I did this.
    For the purposes of the test I left everything that way instead of
    fighting defaults.
    """
    plist_bin = base64.b64decode("""
YnBsaXN0MDDaAQIDBAUGBwgJCgsMDQ4PEAwSExdTaXM5VmlzVHJ1ZVVpc1VpZFRpc1BpVmlzRGF0
YVdpc0ZhbHNlVmlzTm9uZVNmb29XaXNBcnJheVdpc1RvZGF5EAkAgTA5I0AJHrhgAAAARAECA/8I
CVNiYXKjFBUWUTFRMlEzM0G0a0uAAAAACB0hKC4zOkJJTVVdX2BjbHFyc3d7fX+BAAAAAAAAAQEA
AAAAAAAAGAAAAAAAAAAAAAAAAAAAAIo=""")
    plist_dict = {
      'foo': 'bar',
      'is9': 9,
      'isUid': plist.AppleUid(12345),
      'isArray': ['1', '2', '3'],
      'isData': plist.AppleData('\x01\x02\x03\xff'),
      'isFalse': False,
      'isTrue': None,  # see docstring
      'isPi': 3.1400001049041748,
      'isToday': datetime.datetime(2011, 11, 10, 0, 0, tzinfo=plist.UTC()),
      'isNone': None,  # see docstring
    }
    self.PlistTest(plist_bin, plist_dict)

  def testIntegrationTestBinaryToXML(self):
    """Test binary load and XML output.

    Integration test between binary load and XML output.
    """
    plist_bin = base64.b64decode("""
YnBsaXN0MDDZAQIDBAUGBwgJCgsMDQ4PEBESU2lzOVZpc1RydWVVaXNVaWRUaXNQaVdpc0ZhbHNl
VmlzRGF0YVNmb29XaXNUb2RheVdpc0FycmF5EAkJgTA5IkBI9cMIRAECA/9TYmFyM0G0a0uAAAAA
oxMUFVExUTJRMwgbHyYsMTlARExUVldaX2BlaXJ2eHoAAAAAAAABAQAAAAAAAAAWAAAAAAAAAAAA
AAAAAAAAfA==""")
    plist_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '  <dict>\n'
        '    <key>isArray</key>\n'
        '    <array>\n'
        '      <string>1</string>\n'
        '      <string>2</string>\n'
        '      <string>3</string>\n'
        '    </array>\n'
        '    <key>is9</key>\n'
        '    <integer>9</integer>\n'
        '    <key>isData</key>\n'
        '    <data>AQID/w==</data>\n'
        '    <key>isTrue</key>\n'
        '    <true/>\n'
        '    <key>isUid</key>\n'
        '    <dict><key>CF$UID</key><integer>12345</integer></dict>\n'
        '    <key>isFalse</key>\n'
        '    <false/>\n'
        '    <key>isToday</key>\n'
        '    <date>2011-11-10T00:00:00Z</date>\n'
        '    <key>isPi</key>\n'
        '    <real>3.140000</real>\n'
        '    <key>foo</key>\n'
        '    <string>bar</string>\n'
        '  </dict>\n'
        '</plist>\n'
    )
    self.apl.LoadPlist(plist_bin)
    self.apl.Parse()
    self.assertEqual(plist_xml, self.apl.GetXml())

  def testLessBasic(self):
    """Test with a more complex plist that should parse OK."""
    plist_xml = """
        <plist>
        <dict>
          <key>receipts</key>
          <array>
            <dict>
              <key>foo</key>
              <string>bar</string>
            </dict>
            <dict>
              <key>zoo</key>
              <string>omg</string>
            </dict>
            <dict>
              <key>hoo</key>
              <date>2010-10-21T16:30:32Z</date>
            </dict>
          </array>
        </dict>
        </plist>
        """

    plist_dict = {
        'receipts': [
            {'foo': 'bar'},
            {'zoo': 'omg'},
            {'hoo': plist.datetime.datetime(2010, 10, 21, 16, 30, 32)},
        ]
    }
    self.PlistTest(plist_xml, plist_dict)

  def testReal(self):
    """Test with a real plist from Munki."""
    plist_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//XXXXX Computer//DTD PLIST 1.0//EN" "http://www.aaaaa.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>RestartAction</key>
  <string>RequireRestart</string>
  <key>catalogs</key>
  <array>
    <string>production</string>
  </array>
  <key>description</key>
  <string>Includes PhotoI 08.</string>
  <key>display_name</key>
  <string>PhotoI 08</string>
  <key>installed_size</key>
  <integer>534412</integer>
  <key>installer_item_location</key>
  <string>apps/LifeI08/LifeI08.dmg</string>
  <key>installer_item_size</key>
  <integer>3708030</integer>
  <key>minimum_os_version</key>
  <string>10.4.0</string>
  <key>name</key>
  <string>LifeI08_PhotoI</string>
  <key>installer_choices_xml</key>
  <array>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>BandRecorder</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>TunesI</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <true/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>PhotoI</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>MovieI</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>DVDI</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>DVDIExtraContent</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>WebI</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>BandRecorderExtraContent</string>
    </dict>
    <dict>
      <key>attributeSetting</key>
      <false/>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>LifeISoundEffects</string>
    </dict>
  </array>
  <key>receipts</key>
  <array>
    <dict>
      <key>installed_size</key>
      <integer>139130</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.PhotoI</string>
      <key>version</key>
      <string>8.0.0.0.0</string>
    </dict>
    <dict>
      <key>installed_size</key>
      <integer>392900</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.PhotoIContent</string>
      <key>version</key>
      <string>8.0.0.0.0</string>
    </dict>
    <dict>
      <key>installed_size</key>
      <integer>10</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.LifeI08</string>
      <key>version</key>
      <string>8.0.0.0.0</string>
    </dict>
    <dict>
      <key>installed_size</key>
      <integer>10</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.LifeICookie</string>
      <key>version</key>
      <string>8.0.0.0.0</string>
    </dict>
    <dict>
      <key>installed_size</key>
      <integer>321</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.XXXXXIntermediateCodec</string>
      <key>version</key>
      <string>1.2.0.0.0</string>
    </dict>
    <dict>
      <key>installed_size</key>
      <integer>2041</integer>
      <key>packageid</key>
      <string>com.aaaaa.pkg.LifeIMediaBrowser</string>
      <key>version</key>
      <string>2.0.0.0.0</string>
    </dict>
  </array>
  <key>uninstall_method</key>
  <string>removepackages</string>
  <key>uninstallable</key>
  <true/>
  <key>version</key>
  <string>7.0.0.0.0</string>
</dict>
</plist>
"""
    plist_dict = {
      'RestartAction':
      'RequireRestart',
      'catalogs':
      [
        'production',
      ],
      'description':
      'Includes PhotoI 08.',
      'display_name':
      'PhotoI 08',
      'installed_size':
      534412,
      'installer_item_location':
      'apps/LifeI08/LifeI08.dmg',
      'installer_item_size':
      3708030,
      'minimum_os_version':
      '10.4.0',
      'name':
      'LifeI08_PhotoI',
      'installer_choices_xml':
      [
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'BandRecorder',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'TunesI',
        },
        {
          'attributeSetting':
          True,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'PhotoI',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'MovieI',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'DVDI',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'DVDIExtraContent',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'WebI',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'BandRecorderExtraContent',
        },
        {
          'attributeSetting':
          False,
          'choiceAttribute':
          'selected',
          'choiceIdentifier':
          'LifeISoundEffects',
        },
      ],
      'receipts':
      [
        {
          'installed_size':
          139130,
          'packageid':
          'com.aaaaa.pkg.PhotoI',
          'version':
          '8.0.0.0.0',
        },
        {
          'installed_size':
          392900,
          'packageid':
          'com.aaaaa.pkg.PhotoIContent',
          'version':
          '8.0.0.0.0',
        },
        {
          'installed_size':
          10,
          'packageid':
          'com.aaaaa.pkg.LifeI08',
          'version':
          '8.0.0.0.0',
        },
        {
          'installed_size':
          10,
          'packageid':
          'com.aaaaa.pkg.LifeICookie',
          'version':
          '8.0.0.0.0',
        },
        {
          'installed_size':
          321,
          'packageid':
          'com.aaaaa.pkg.XXXXXIntermediateCodec',
          'version':
          '1.2.0.0.0',
        },
        {
          'installed_size':
          2041,
          'packageid':
          'com.aaaaa.pkg.LifeIMediaBrowser',
          'version':
          '2.0.0.0.0',
        },
      ],
      'uninstall_method':
      'removepackages',
      'uninstallable':
      True,
      'version':
      '7.0.0.0.0',
    }

    self.PlistTest(plist_xml, plist_dict)


class MunkiPlistTest(mox.MoxTestBase):
  """Test MunkiPlist class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.munki = plist.MunkiPlist()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()


class MunkiManifestPlistTest(mox.MoxTestBase):
  """Test MunkiManifestPlist class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.munki = plist.MunkiManifestPlist()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testParseSuccess(self):
    """Test Parse() with valid Manifest plist."""
    self.munki.LoadDocument(
        '<plist><dict><key>catalogs</key><array><string>hello</string></array>'
        '<key>managed_installs</key><array><string>hello</string></array>'
        '</dict></plist>')
    self.munki.Parse()

  def testParseMissingCatalogsList(self):
    """Test Parse() with missing catalogs."""
    self.munki.LoadDocument(
        '<plist><dict><key>managed_installs</key><array></array>'
        '</dict></plist>')
    self.assertRaises(
        plist.InvalidPlistError, self.munki.Parse)

  def testParseInvalidCatalogsList(self):
    """Test Parse() with an invalid catalogs list."""
    self.munki.LoadDocument(
        '<plist><dict><key>catalogs</key><string>hello</string>'
        '<key>managed_installs</key><array><string>hello</string></array>'
        '</dict></plist>')
    self.assertRaises(
        plist.InvalidPlistError, self.munki.Parse)


class MunkiPackageInfoPlistTest(mox.MoxTestBase):
  """Test MunkiPackageInfoPlist class."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.munki = plist.MunkiPackageInfoPlist()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testParseSuccess(self):
    """Test Parse() with valid Package Info plist."""
    self.munki.LoadDocument(
        '<plist><dict><key>catalogs</key><array><string>hello</string></array>'
        '<key>installer_item_location</key><string>good location</string>'
        '</dict></plist>')
    self.munki.Parse()

  def testParseMissingInstallerItemLocation(self):
    """Test Parse() with missing installer_item_location."""
    self.munki.LoadDocument(
        '<plist><dict><key>catalogs</key>'
        '<array><string>hello</string></array></dict></plist>')
    self.assertRaises(
        plist.InvalidPlistError, self.munki.Parse)

  def testParseInvalidCatalogsList(self):
    """Test Parse() with an invalid catalogs list."""
    self.munki.LoadDocument(
        '<plist><dict><key>catalogs</key><string>hello</string>'
        '<key>installer_item_location</key><string>good location</string>'
        '</dict></plist>')
    self.assertRaises(
        plist.InvalidPlistError, self.munki.Parse)

  def testGetPackageName(self):
    """Tests the _GetPackageName()."""
    name = 'foo pkg name'
    self.munki._plist = {'name': name}
    self.mox.ReplayAll()
    self.assertEqual(name, self.munki.GetPackageName())
    self.mox.VerifyAll()

  def testGetPackageNameWhereNameNotInPkginfo(self):
    """Tests the _GetPackageName() where name not in pkginfo."""
    self.munki._plist = {}
    self.mox.ReplayAll()
    self.assertRaises(plist.PlistError, self.munki.GetPackageName)
    self.mox.VerifyAll()

  def testSetDescription(self):
    """Test SetDescription()."""
    self.munki._plist = {}
    self.munki.SetDescription('foo')
    self.assertEqual(self.munki._plist['description'], 'foo')

  def testSetDisplayName(self):
    """Test SetDisplayName()."""
    self.munki._plist = {}
    self.munki.SetDisplayName('foo')
    self.assertEqual(self.munki._plist['display_name'], 'foo')

  def testSetForcedInstall(self):
    """Test SetForcedInstall()."""
    self.munki._plist = {}
    self.munki.SetForcedInstall(True)
    self.assertTrue(self.munki._plist['forced_install'])
    self.munki.SetForcedInstall(False)
    self.assertTrue('forced_install' not in self.munki._plist)
    self.munki.SetForcedInstall(False)
    self.assertTrue('forced_install' not in self.munki._plist)

  def testSetCatalogs(self):
    """Test SetCatalogs()."""
    self.munki._plist = {}
    # Note: here we are also testing the changed flag
    self.assertFalse(self.munki._changed)
    self.munki.SetCatalogs(['hi'])
    self.assertEqual(self.munki._plist['catalogs'], ['hi'])
    self.assertTrue(self.munki._changed)

  def testHasChanged(self):
    """Test HasChanged()."""
    self.munki._changed = True
    self.assertTrue(self.munki.HasChanged())
    self.assertFalse(self.munki._changed)

  def testSetChanged(self):
    """Test SetChanged()."""
    self.munki.SetChanged()
    self.assertTrue(self.munki._changed)

  def testEq(self):
    """Test __eq__."""
    other = plist.MunkiPackageInfoPlist()
    other._plist = { 'foo': 1 }
    self.munki._plist = { 'foo': 1 }
    self.assertFalse(id(other._plist) == id(self.munki._plist))
    self.assertTrue(self.munki == other)
    self.assertFalse(self.munki == { 'foo': 1 })
    self.assertFalse(self.munki == self)
    other._plist = { 'foo': 2 }
    self.assertFalse(self.munki == other)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()