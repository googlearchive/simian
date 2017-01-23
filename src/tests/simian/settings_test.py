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
"""settings module tests."""

import os
import random
import re
import sys
import types

import mox
import stubout

from google.apputils import app
from google.apputils import basetest

# Set an environment variable so the settings module knows when it's being
# tested directly, versus used for testing other modules.
os.environ['____TESTING_SETTINGS_MODULE'] = 'yes'
from simian import settings
del(os.environ['____TESTING_SETTINGS_MODULE'])


class SettingsModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testConstants(self):
    self.assertTrue(hasattr(settings, 'GAE'))
    self.assertTrue(hasattr(settings, 'DEV_APPSERVER'))
    self.assertTrue(hasattr(settings, 'DEBUG'))
    self.assertTrue(hasattr(settings, 'TESTING'))
    self.assertTrue(hasattr(settings, 'SETTINGS_TESTING'))
    self.assertFalse(settings.GAE)
    self.assertFalse(settings.DEV_APPSERVER)
    self.assertFalse(settings.DEBUG)
    self.assertTrue(settings.TESTING)
    self.assertTrue(settings.SETTINGS_TESTING)


class BaseSettingsTestBase(mox.MoxTestBase):
  """Base test class for all BaseSettings derived class tests."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    if self.__class__.__name__ == 'BaseSettingsTestBase':
      return

    self.module = self._GenerateModule()
    self.settings_class = self._GetSettingsClassUnderTest()

    # Derive a class from this class that plugs in the test _Globals()
    # function. This makes testing more predictable as the contents
    # of the settings module may change at any time.
    class DerivedSettingsClass(self.settings_class):
      def _Globals(xself):  # pylint: disable=no-self-argument
        """Returns globals dict like globals()."""
        return self._Globals()
    self.settings = DerivedSettingsClass(self.module)

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GetSettingsClassUnderTest(self):
    """Override to return the class under test."""
    raise NotImplementedError

  def _Globals(self):
    """Returns globals dict like globals()."""
    return globals()

  def _GenerateModule(self):
    """Return a module instance to pass to the settings class under test."""
    self.module_name = self._GetSettingsClassUnderTest().__name__
    return types.ModuleType(self.module_name)

  def _TestNotImplemented(self, method_name, *args, **kwargs):
    """Helper function to test NotImplementedError on a method.

    Args:
      method_name: str, method name on self.settings to call
      args: args to pass
      kwargs: kwargs to pass
    """
    self.assertRaises(
        NotImplementedError,
        getattr(self.settings, method_name),
        *args,
        **kwargs)


class BaseSettingsTest(BaseSettingsTestBase):
  """Test BaseSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.BaseSettings

  def testInitialize(self):
    """Test _Initialize()."""

  def testPopulateGlobal(self):
    """Test _PopulateGlobals()."""
    global_vars = {
        'FOO': 1,
        'bar': 2,
    }

    self.mox.StubOutWithMock(self.settings, '_Set')
    globals_ = self.mox.CreateMockAnything()

    globals_().AndReturn(global_vars)
    globals_().AndReturn(global_vars)
    globals_().AndReturn(global_vars)
    self.settings._Set('foo', 1)

    self.mox.ReplayAll()
    self.settings._PopulateGlobals(globals_=globals_)
    self.mox.VerifyAll()

  def testPopulateGlobalWithSetFunc(self):
    """Test _PopulateGlobals() with set_func."""
    global_vars = {
        'FOO': 1,
        'bar': 2,
    }

    set_func = self.mox.CreateMockAnything()
    globals_ = self.mox.CreateMockAnything()

    globals_().AndReturn(global_vars)
    globals_().AndReturn(global_vars)
    globals_().AndReturn(global_vars)
    set_func('foo', 1)

    self.mox.ReplayAll()
    self.settings._PopulateGlobals(set_func=set_func, globals_=globals_)
    self.mox.VerifyAll()

  def testGet(self):
    """Test _Get()."""
    self._TestNotImplemented('_Get', 'k')

  def testSet(self):
    """Test _Set()."""
    self._TestNotImplemented('_Set', 'k', 'v')

  def testDir(self):
    """Test _Dir()."""
    self._TestNotImplemented('_Dir')

  def testCheckValueRegex(self):
    """Test _CheckValueRegex()."""
    self.settings._CheckValueRegex('k', 'foo', '^foo$')
    self.settings._CheckValueRegex('k', 'foo', settings.re.compile('^foo$'))
    self.assertRaises(
        ValueError,
        self.settings._CheckValueRegex,
        'k', 'bar', '^foo$')

  def testCheckValueFunc(self):
    """Test _CheckValueFunc()."""
    func_foo = lambda k, v: v == 'foo'
    func_bar = lambda k, v: v == 'bar'

    self.assertRaises(
        TypeError, self.settings._CheckValueFunc, 'k', 'foo','not callable')
    self.settings._CheckValueFunc('k', 'foo', func_foo)
    self.assertRaises(
        ValueError, self.settings._CheckValueFunc, 'k', 'foo', func_bar)

  def testCheckValuePemX509Cert(self):
    """Test CheckValuePemX509Cert()."""
    k = 'k'
    pem_cert = 'pem'

    self.mox.StubOutWithMock(settings.x509, 'LoadCertificateFromPEM')
    settings.x509.LoadCertificateFromPEM(pem_cert).AndReturn('cert')

    self.mox.ReplayAll()
    self.assertTrue(self.settings.CheckValuePemX509Cert(k, pem_cert) is None)
    self.mox.VerifyAll()

  def testCheckValuePemX509CertWhenBadlyFormed(self):
    """Test CheckValuePemX509Cert()."""
    k = 'k'
    pem_cert = 'pem'

    self.mox.StubOutWithMock(settings.x509, 'LoadCertificateFromPEM')
    settings.x509.LoadCertificateFromPEM(pem_cert).AndRaise(
        settings.x509.Error)

    self.mox.ReplayAll()
    self.assertRaises(
        ValueError, self.settings.CheckValuePemX509Cert, k, pem_cert)
    self.mox.VerifyAll()

  def testCheckValuePemRsaPrivateKey(self):
    """Test CheckValuePemRsaPrivateKey()."""
    k = 'k'
    pem_cert = 'pem'

    self.mox.StubOutWithMock(settings.x509, 'LoadRSAPrivateKeyFromPEM')
    settings.x509.LoadRSAPrivateKeyFromPEM(pem_cert).AndReturn('key')

    self.mox.ReplayAll()
    self.assertTrue(
        self.settings.CheckValuePemRsaPrivateKey(k, pem_cert) is None)
    self.mox.VerifyAll()

  def testCheckValuePemRsaPrivateKeyWhenBadlyFormed(self):
    """Test CheckValuePemRsaPrivateKey()."""
    k = 'k'
    pem_cert = 'pem'

    self.mox.StubOutWithMock(settings.x509, 'LoadRSAPrivateKeyFromPEM')
    settings.x509.LoadRSAPrivateKeyFromPEM(pem_cert).AndRaise(
        settings.x509.Error)

    self.mox.ReplayAll()
    self.assertRaises(
        ValueError, self.settings.CheckValuePemRsaPrivateKey, k, pem_cert)
    self.mox.VerifyAll()

  def testCheckValidation(self):
    """Test _CheckValidation()."""
    self.mox.StubOutWithMock(self.settings, self.settings._VALIDATION_REGEX)
    self.settings._validation = {
        'foo': {
            self.settings._VALIDATION_REGEX: ['^bar$'],
        }}

    self.settings._CheckValueRegex('foo', 'bar', '^bar$').AndReturn(None)

    self.mox.ReplayAll()
    self.settings._CheckValidation('dne', 'other crap')
    self.settings._CheckValidation('foo', 'bar')
    self.mox.VerifyAll()

  def testSetValidation(self):
    """Test SetValidation()."""
    k = 'foo'
    v = 'arg'

    validation_type = self.settings._VALIDATION_TYPES[0] + 'junk'
    self.assertFalse(validation_type in self.settings._VALIDATION_TYPES)
    self.assertRaises(
        ValueError,
        self.settings._SetValidation, validation_type, 'junk')

    validation_type = self.settings._VALIDATION_TYPES[0]
    self.settings._SetValidation(k, validation_type, v)
    self.assertEqual(
        self.settings._validation,
        {k: { validation_type: (v,) }})

  def testGetValidationRegex(self):
    """Test GetValidationRegex()."""
    regex = 'REGEX'
    self.settings._validation = {
        'foo': {self.settings._VALIDATION_REGEX: [regex]},
        'bar': {},
    }
    self.assertTrue(self.settings.GetValidationRegex('dne') is None)
    self.assertTrue(self.settings.GetValidationRegex('bar') is None)
    self.assertEqual(self.settings.GetValidationRegex('foo'), regex)

  def testGetattr(self):
    """Test __getattr__()."""
    self.mox.StubOutWithMock(self.settings, '_Get')

    self.settings._Get('foo').AndReturn(2)
    self.settings._Get('dne').AndRaise(AttributeError('DNE'))
    self.settings._Get('dne').AndRaise(AttributeError('non conform'))

    self.mox.ReplayAll()
    self.assertEqual(self.settings._is_class, 1)
    self.assertEqual(self.settings.foo, 2)
    self.assertRaises(
        AttributeError,
        getattr,
        self.settings,
        'DNE')
    self.assertRaises(
        AttributeError,
        getattr,
        self.settings,
        'DNE')
    self.assertRaises(
        AttributeError,
        getattr,
        self.settings,
        '_foobar')
    self.mox.VerifyAll()

  def testSetattr(self):
    """Test __setattr__()."""
    self.mox.StubOutWithMock(self.settings, '_Set')
    self.settings._Set('foo', 2)

    self.mox.ReplayAll()
    self.settings.FOO = 2
    self.settings._bar = 1
    self.assertEqual(self.settings.__dict__['_bar'], 1)  # eh?
    self.mox.VerifyAll()

  def testDirPython(self):
    """Test __dir__()."""
    self.mox.StubOutWithMock(self.settings, '_Dir')
    self.settings._Dir().AndReturn(['foo', 'bar'])

    self.mox.ReplayAll()
    # NOTE(user): I am not sure why the return order is backwards.
    self.assertEqual(['FOO', 'BAR'], self.settings.__dir__())
    self.mox.VerifyAll()


class ModuleSettingsTest(BaseSettingsTestBase):
  """Test ModuleSettings."""

  def _GetSettingsClassUnderTest(self):
    # Make a light subclass of ModuleSettings that overrides
    # methods. Goal: make testing of the important parts easier.

    class ModuleSettingsTestModule(settings.ModuleSettings):
      def _LoadSettingsModule(xself):  # pylint: disable=no-self-argument
        k = random.randint(0, 100000)
        self.module_name = 'FOO%s' % k
        sys.modules[self.module_name] = self.module
        return self.module_name

    return ModuleSettingsTestModule

  def testLoadSettingsModule(self):
    """Test _LoadSettingsModule()."""
    self.assertRaises(
        NotImplementedError,
        settings.ModuleSettings,
        self.module)

  def testInitialize(self):
    """Test _Initialize()."""
    self.assertEqual(self.settings._module_name, self.module_name)

  def testGet(self):
    """Test _Get()."""
    self.settings._module.FOO = 'bar'
    self.mox.ReplayAll()
    self.assertEqual('bar', self.settings._Get('foo'))
    self.assertRaises(
        AttributeError,
        self.settings._Get,
        'dne')
    self.mox.VerifyAll()

  def testSet(self):
    """Test _Set()."""
    self.mox.ReplayAll()
    self.settings._Set('foo', 'bar')
    self.assertEqual(self.settings._module.FOO, 'bar')
    self.mox.VerifyAll()


class TestModuleSettingsTest(BaseSettingsTestBase):
  """Test TestModuleSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.TestModuleSettings

  # NOTE(user): Skip unit tests for this class because its operation
  # is clear and testing will be a PITA.


class DictSettingsTest(BaseSettingsTestBase):
  """Test DictSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.DictSettings

  def _Globals(self):
    """Returns globals dict like globals()."""
    return {'FOO': 1}

  def testInitialize(self):
    """Test _Initialize()."""
    self.assertEqual(self.settings._settings, {'foo': 1})

  def testGet(self):
    """Test _Get()."""
    self.assertEqual(self.settings._Get('foo'), 1)
    self.assertRaises(AttributeError, self.settings._Get, 'dne')

  def testSet(self):
    """Test _Set()."""
    self.mox.ReplayAll()
    self.settings._Set('bar', 2)
    self.assertEqual(self.settings._settings['bar'], 2)
    self.mox.VerifyAll()

  def testDir(self):
    self.assertEqual(['foo'], self.settings._Dir())


class SimianDictSettingsTest(BaseSettingsTestBase):
  """Test SimianDictSettings."""

  def _GetSettingsClassUnderTest(self):
    return settings.SimianDictSettings

  def _Globals(self):
    """Returns globals dict like globals()."""
    return {'SERVER_HOSTNAME': 'example.appspot.com'}

  def _CheckSetValidation(self, k, t):
    """Helper to set that validation is set for k with type t.

    Also, validate that _VALIDATION_REGEX type validations compile to
    real well formed regexes.
    """
    self.assertTrue(k in self.settings._validation)
    self.assertTrue(t in self.settings._validation[k])
    self.assertTrue(self.settings._validation[k][t] is not None)
    if t == self.settings._VALIDATION_REGEX:
      unused = re.compile(self.settings._validation[k][t][0])

  def testInitialize(self):
    """Test _Initialize()."""
    regex_key_validations = [
        'email_domain', 'email_sender', 'email_reply_to', 'uuid_lookup_url',
        'owner_lookup_url']
    for k in regex_key_validations:
      self._CheckSetValidation(k, self.settings._VALIDATION_REGEX)

  def testIsCaIdValid(self):
    k = 'k'
    self.assertTrue(self.settings._IsCaIdValid(k, None))
    self.assertTrue(self.settings._IsCaIdValid(k, 'FOO'))
    self.assertFalse(self.settings._IsCaIdValid(k, '9'))
    self.assertFalse(self.settings._IsCaIdValid(k, ''))
    self.assertFalse(self.settings._IsCaIdValid(k, 10))


class FilesystemSettingsTest(BaseSettingsTestBase):
  """Test FilesystemSettings class."""

  def _GetSettingsClassUnderTest(self):
    return settings.FilesystemSettings

  def testTranslateValue(self):
    """Test _TranslateValue()."""
    self.assertEqual(1, self.settings._TranslateValue('1'))
    self.assertEqual(True, self.settings._TranslateValue('True'))
    self.assertEqual('foo', self.settings._TranslateValue('\"foo\"'))
    self.assertEqual('foo', self.settings._TranslateValue('\'foo\''))
    self.assertEqual(
        ['hi', 'there'], self.settings._TranslateValue('[hi, there]'))
    self.assertEqual('', self.settings._TranslateValue(''))

  def testGetExternalConfigurationAsFile(self):
    """Test _GetExternalConfiguration() when as_file=True."""
    mock_open = self.mox.CreateMockAnything()
    mock_fh = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()

    mock_isdir(self.settings._path).AndReturn(True)

    mock_join(self.settings._path, 'name').AndReturn('/path/name')
    mock_open('/path/name', 'r').AndReturn(mock_fh)
    mock_fh.read().AndReturn('value\n')
    mock_fh.close()

    self.mox.ReplayAll()
    self.assertEqual(
        'value', self.settings._GetExternalConfiguration(
            'name', as_file=True,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()

  def testGetExternalConfigurationAsFileWhenNotIsdir(self):
    """Test _GetExternalConfiguration() when as_file=True."""
    mock_open = self.mox.CreateMockAnything()
    mock_fh = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()

    mock_isdir(self.settings._path).AndReturn(False)

    self.mox.ReplayAll()
    self.assertEqual(
        None, self.settings._GetExternalConfiguration(
            'name', as_file=True,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()


  def testGetExternalConfigurationAsFileWhenIoError(self):
    """Test _GetExternalConfiguration() when as_file=True when IOError."""
    mock_open = self.mox.CreateMockAnything()
    mock_fh = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()

    mock_isdir(self.settings._path).AndReturn(True)

    mock_join(self.settings._path, 'name').AndReturn('/path/name')
    mock_open('/path/name', 'r').AndReturn(mock_fh)
    mock_fh.read().AndRaise(IOError)

    self.mox.ReplayAll()
    self.assertEqual(
        None, self.settings._GetExternalConfiguration(
            'name', as_file=True,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()

  def testGetExternalConfiguration(self):
    """Test _GetExternalConfiguration() when as_file=False."""
    mock_open = self.mox.CreateMockAnything()
    mock_fh = self.mox.CreateMockAnything()
    mock_cp = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(settings.ConfigParser, 'ConfigParser', True)
    self.mox.StubOutWithMock(self.settings, '_TranslateValue')

    mock_isdir(self.settings._path).AndReturn(True)

    mock_join(self.settings._path, 'name').AndReturn('/path/name')
    mock_open('/path/name.cfg', 'r').AndReturn(mock_fh)
    settings.ConfigParser.ConfigParser().AndReturn(mock_cp)
    mock_cp.readfp(mock_fh)
    mock_fh.close()
    mock_cp.items('settings').AndReturn(
        (('name2', 'value2'), ('name', 'value')))
    self.settings._TranslateValue('value2').AndReturn('value2')
    self.settings._TranslateValue('value').AndReturn('value')

    self.mox.ReplayAll()
    self.assertEqual(
        {'name2': 'value2', 'name': 'value'},
        self.settings._GetExternalConfiguration(
            'name', as_file=False,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()

  def testGetExternalConfigurationWhenConfigParserError(self):
    """Test _GetExternalConfiguration() when as_file=False and CP.Error."""
    mock_open = self.mox.CreateMockAnything()
    mock_fh = self.mox.CreateMockAnything()
    mock_cp = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(settings.ConfigParser, 'ConfigParser', True)

    mock_isdir(self.settings._path).AndReturn(True)

    mock_join(self.settings._path, 'name').AndReturn('/path/name')
    mock_open('/path/name.cfg', 'r').AndReturn(mock_fh)
    settings.ConfigParser.ConfigParser().AndReturn(mock_cp)
    mock_cp.readfp(mock_fh).AndRaise(settings.ConfigParser.Error)

    self.mox.ReplayAll()
    self.assertEqual(
        None,
        self.settings._GetExternalConfiguration(
            'name', as_file=False,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()

  def testGetExternalConfigurationWhenIoError(self):
    """Test _GetExternalConfiguration() when as_file=False and IOError."""
    mock_open = self.mox.CreateMockAnything()
    mock_isdir = self.mox.CreateMockAnything()
    mock_join = self.mox.CreateMockAnything()

    mock_isdir(self.settings._path).AndReturn(True)

    mock_join(self.settings._path, 'name').AndReturn('/path/name')
    mock_open('/path/name.cfg', 'r').AndRaise(IOError)

    self.mox.ReplayAll()
    self.assertEqual(
        None,
        self.settings._GetExternalConfiguration(
            'name', as_file=False,
            open_=mock_open, isdir_=mock_isdir, join_=mock_join))
    self.mox.VerifyAll()

  def testGetExternalPem(self):
    """Test _GetExternalPem()."""
    self.mox.StubOutWithMock(self.settings, '_GetExternalConfiguration')

    path = os.path.join(self.settings._path, 'ssl')

    self.settings._GetExternalConfiguration(
        'new.pem', as_file=True, path=path).AndReturn('new')

    self.settings._settings['predefined'] = 'pre'

    self.mox.ReplayAll()
    self.assertEqual('pre', self.settings._GetExternalPem('predefined'))
    self.assertEqual('new', self.settings._GetExternalPem('new_pem'))
    self.assertEqual(self.settings._settings['new_pem'], 'new')
    self.mox.VerifyAll()

  def testGetExternalPemWhenMissing(self):
    """Test _GetExternalPem()."""
    self.mox.StubOutWithMock(self.settings, '_GetExternalConfiguration')

    path = os.path.join(self.settings._path, 'ssl')
    self.settings._GetExternalConfiguration(
        'new.pem', as_file=True, path=path).AndReturn(None)

    self.mox.ReplayAll()
    self.assertRaises(
        AttributeError, self.settings._GetExternalPem, 'new_pem')
    self.mox.VerifyAll()

  def testGetExternalValue(self):
    """Test _GetExternalValue()."""
    self.mox.StubOutWithMock(self.settings, '_GetExternalConfiguration')

    # 1
    self.settings._settings['predefined'] = 'pre'
    # 2
    self.settings._GetExternalConfiguration('settings').AndReturn({'new2': 1})
    # 3
    self.settings._GetExternalConfiguration('settings').AndReturn({'new': 1})
    # 4
    self.settings._GetExternalConfiguration('settings').AndReturn(None)

    self.mox.ReplayAll()
    # 1
    self.assertEqual('pre', self.settings._GetExternalValue('predefined'))
    # 2
    self.assertRaises(
        AttributeError,
        self.settings._GetExternalValue,
        'not-new')
    # 3
    self.assertEqual(1, self.settings._GetExternalValue('new'))
    self.assertEqual(self.settings._settings['new'], 1)
    # 4
    self.assertRaises(
        AttributeError,
        self.settings._GetExternalValue,
        'other')
    self.mox.VerifyAll()

  def testGet(self):
    """Test _Get()."""
    self.mox.StubOutWithMock(self.settings, '_GetExternalPem')
    self.mox.StubOutWithMock(self.settings, '_GetExternalValue')
    self.settings._GetExternalPem('foo_pem').AndReturn(0)
    self.settings._GetExternalValue('foo_item').AndReturn(1)
    self.mox.ReplayAll()
    self.assertEqual(0, getattr(self.settings, 'foo_pem'))
    self.assertEqual(1, getattr(self.settings, 'foo_item'))
    self.mox.VerifyAll()

  def testDir(self):
    """Test _Dir()."""
    self._TestNotImplemented('_Dir')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
