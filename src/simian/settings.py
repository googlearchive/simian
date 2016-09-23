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
"""Configurable settings module."""

import ConfigParser
import importlib
import logging
import os
import re
import sys
import types

from simian.auth import x509

# If True, all domain users have (readonly) access to web UI. If False, only
# define admins, support, security, etc. users have access.
# TODO(user): move setting to Datastore.
ALLOW_ALL_DOMAIN_USERS_READ_ACCESS = False
ALLOW_SELF_REPORT = True

# Automatic values:
# True if running in debug mode.
DEBUG = False
# True if running in dev_appserver.
DEV_APPSERVER = False
# True if running in Google App Engine.
GAE = False
# True if running in unit testing environment.
TESTING = False
# True if running in unit testing environment and settings_test is under test.
SETTINGS_TESTING = False

ENTITIES_PER_DEFERRED_TASK = 1000

if (os.environ.get('SERVER_SOFTWARE', '').startswith('Development') and
    'testbed' not in os.environ.get('SERVER_SOFTWARE', '')):
  logging.getLogger().setLevel(logging.DEBUG)
  DEBUG = True
  DEV_APPSERVER = True
  GAE = True
elif os.environ.get('SERVER_SOFTWARE', '').startswith('Google App Engine'):
  GAE = True

# If unit tests for this module are running, set SETTINGS_TEST to True.
if os.environ.get('____TESTING_SETTINGS_MODULE'):
  SETTINGS_TESTING = True

# If unit tests are running, set TESTING to True.
if 'unittest2' in sys.modules or 'unittest' in sys.modules:
  TESTING = True

if GAE:
  SERVER_HOSTNAME = os.environ.get('DEFAULT_VERSION_HOSTNAME')

# To require a second administrator to approve changes set this to True.
APPROVAL_REQUIRED = False

# To allow a group of non-admin users to make proposals set this to True.
ENABLE_PROPOSALS_GROUP = False



class BaseSettings(types.ModuleType):
  """Base class for a settings container that acts like a module.

  An instance of this class can replace a loaded module to provide read and
  write access to settings variables via attribute access.

  Don't use this class directly, use a child class.

  Child classes should implement:
    - _Get()
    - _Set()
    - _Dir()

  Child classes can optionally implement:
    - _Initialize()
    - _PopulateGlobals()
    - _CheckValidation()

  Child classes can use these helper functions to configure themselves:
    - _SetValidation()

  This class will do a few things upon initialization:
    - Copy attributes from the module e.g. __author__
    - Run _PopulateGlobals(), which will:
      - Copy already defined CONSTANTS into the settings
      - Override this method in subclasses if this feature is undesired.
    - Call _Initialize() which provides for per-class initialization.

  Due to code style requirements where constants should be UPPERCASE,
  BaseSettings is very specific about attribute and key name case handling.

  No matter how subclass underlying code stores key/value pairs, the
  settings attributes will always be made available via "UPPER_CASE_NAME".
  The _Get() and _Set() methods will always receive the corresponding
  "upper_case_name".

  e.g.
    settings.FOO          =>  _Get('foo')
    settings.FOO = 'bar'  =>  _Set('foo', 'bar')
  """

  # These constant values should match the method names that perform
  # the validation.
  _VALIDATION_REGEX = '_CheckValueRegex'
  _VALIDATION_FUNC = '_CheckValueFunc'
  _VALIDATION_PEM_X509_CERT = 'CheckValuePemX509Cert'
  _VALIDATION_PEM_RSA_PRIVATE_KEY = 'CheckValuePemRsaPrivateKey'
  _VALIDATION_TYPES = [
      _VALIDATION_REGEX, _VALIDATION_FUNC,
      _VALIDATION_PEM_X509_CERT, _VALIDATION_PEM_RSA_PRIVATE_KEY]

  def __init__(self, module, *args, **kwargs):
    """Init.

    Args:
      module: module, the module that this class instance is replacing.
    """
    # pylint: disable=non-parent-init-called
    types.ModuleType.__init__(self, module.__name__, *args, **kwargs)
    self._module = module
    if hasattr(module, '__doc__'):
      self.__doc__ = module.__doc__
    if hasattr(module, '__author__'):
      self.__author__ = module.__author__
    self._is_class = 1
    self._validation = {}
    self._Initialize()
    self._PopulateGlobals()

  def _Initialize(self):
    """Initialize the class.

    Example usage: set up the storage that will be used for settings.

    DO NOT call superclass _Initialize() methods!
    This method will remain specific to each class.
    """
    pass  # intentional

  def _Globals(self):
    """Return globals() or an overridden value."""
    return globals()

  def _PopulateGlobals(self, set_func=None, globals_=None):
    """Find global VARIABLES and load them as settings, if possible.

    Args:
      set_func: function, otherwise defaults to self._Set. Replacement
        function should follow the same interface.
      globals_: function, default globals, return all global variables
        as dict.
    """
    if set_func is None:
      set_func = self._Set
    if globals_ is None:
      globals_ = self._Globals
    for k in globals_():
      if k.upper() == k and not callable(globals_()[k]):
        try:
          set_func(k.lower(), globals_()[k])
        except NotImplementedError:
          break

  def _Get(self, k):
    """Get one settings item.

    Args:
      k: str, name to get. The name will always be in lowercase.
    Returns:
      any settings value
    Raises:
      NotImplementedError: if this method is not implemented.
      AttributeError(k): if this settings item does not exist.
    """
    raise NotImplementedError

  def _Set(self, k, v):
    """Set one settings item.

    Args:
      k: str, name to set. The name will always be in lowercase.
      v: str, value to set.
    Raises:
      NotImplementedError: if this method is not implemented.
    """
    raise NotImplementedError

  def _Dir(self):
    """Returns directory of all settings names as a list.

    Raises:
      NotImplementedError: if this method is not implemented.
    """
    raise NotImplementedError

  def _CheckValueRegex(self, k, v, regex):
    """Check whether v meets regex validation for setting k.

    Args:
      k: str, settings name.
      v: any value.
      regex: str or compiled re.RegexObject.
    Returns:
      None if the value is appropriate and can be set.
    Raises:
      ValueError: if the value is not appropriately formed to be set for k.
    """
    if isinstance(regex, basestring):
      regex = re.compile(regex)

    m = regex.search(str(v))
    if m is None:
      raise ValueError('Invalid value "%s" for %s' % (v, k))

  def _CheckValueFunc(self, k, v, func):
    """Check whether v meets func validation for setting k.

    Args:
      k: str, name.
      v: any value.
      func: func, callable, call and expect True/False.
    Returns:
      None if the value is appropriate and can be set.
    Raises:
      ValueError: if the value is not appropriately formed to be set for k.
    """
    if not callable(func):
      raise TypeError('func is not callable')

    b = func(k, v)

    if b == True:
      return

    raise ValueError('value "%s" for %s' % (v, k))

  def CheckValuePemX509Cert(self, _, v):
    """Check whether v meets PEM cert validation for setting k.

    Args:
      _: str, name, unused.
      v: any value.
    Returns:
      None if the value is appropriate and can be set.
    Raises:
      ValueError: if the value is not appropriately formed to be set for k.
    """
    try:
      _ = x509.LoadCertificateFromPEM(v)
    except x509.Error, e:
      raise ValueError(str(e))

  def CheckValuePemRsaPrivateKey(self, _, v):
    """Check whether v meets PEM RSA priv key validation for settings k.

    Args:
      _: str, name, unused..
      v: any value.
    Returns:
      None if the value is appropriate and can be set.
    Raises:
      ValueError: if the value is not appropriately formed to be set for k.
    """
    try:
      _ = x509.LoadRSAPrivateKeyFromPEM(v)
    except x509.Error, e:
      raise ValueError(str(e))

  def _CheckValidation(self, k, v):
    """Check whether v is an appropriate value for settings k.

    Args:
      k: str, name.
      v: any value.
    Returns:
      None if the value is appropriate and can be set.
    Raises:
      ValueError: if the value is not appropriately formed to be set for k.
    """
    if k not in self._validation:
      return

    for validation_type in self._validation[k]:
      # The validation_type str is also the name of the method to call
      # to perform the value check.
      getattr(self, validation_type)(
          k, v, *self._validation[k][validation_type])

  def _SetValidation(self, k, t, *validation):
    """Set validation on setting k.

    Args:
      k: str, name.
      t: str, type of validation, in self._VALIDATION_TYPES
      *validation: data to supply as validation data to validation func.
    Raises:
      ValueError: if t is invalid.
    """
    if t not in self._VALIDATION_TYPES:
      raise ValueError(t)

    if k not in self._validation:
      self._validation[k] = {}

    self._validation[k][t] = validation

  def GetValidationRegex(self, k):
    """Get regex validation for setting k.

    Args:
      k: str, name.
    Returns:
      str regex validation if one exists, otherwise None.
    """
    if k not in self._validation:
      return None

    return self._validation[k].get(self._VALIDATION_REGEX, [None])[0]

  def CheckValidation(self, k=None):
    """Check validation for setting k, or default all.

    Args:
      k: str, optional, name.
    Returns:
      None if all settings values are OK.
    Raises:
      ValueError: if setting value is invalid.
    """
    if k is not None:
      if k not in self._settings:
        return
      settings_keys = [k]
    else:
      settings_keys = self._settings.keys()
    for k in settings_keys:
      self._CheckValidation(k, self._settings[k])

  def __getattr__(self, k):
    """Returns value for attribute with name k.

    Args:
      k: str, name.
    Returns:
      value at k.
    Raises:
      AttributeError: if this attribute does not exist.
    """
    if k.startswith('_'):
      if k in self.__dict__:
        return self.__dict__[k]
      else:
        raise AttributeError(k)
    else:
      try:
        return self._Get(str(k).lower())
      except AttributeError, e:
        if e.args[0] == k:
          raise AttributeError(str(k).upper())
        raise

  def __setattr__(self, k, v):
    """Sets attribute value at name k with value v.

    Args:
      k: str, name.
      v: any value, value.
    """
    if k.startswith('_'):
      self.__dict__[k] = v
    else:
      self._Set(str(k).lower(), v)

  def __dir__(self):
    """Returns list of all attribute names."""
    return [x.upper() for x in self._Dir()]


class ModuleSettings(BaseSettings):
  """Settings that uses another module for storage.

  Don't use this class directly, use a child class.
  """

  def _LoadSettingsModule(self):
    """Load the module used for settings storage and return its full name."""
    raise NotImplementedError

  def _Initialize(self):
    """Initialize the settings storage.

    Raises:
      NotImplementedError: if module access fails.
    """
    self._module_name = self._LoadSettingsModule()
    try:
      self._module = sys.modules[self._module_name]
    except (KeyError, AttributeError), e:
      raise NotImplementedError(
          'ModuleSettings not implemented correctly: %s' % str(e))

  def _Get(self, k):
    """Get one settings item.

    Args:
      k: str, name to get. The name will always be in lowercase.
    Returns:
      any settings value
    Raises:
      AttributeError: if this settings item does not exist.
    """
    if hasattr(self._module, k.upper()):
      return getattr(self._module, k.upper())
    else:
      raise AttributeError(k)

  def _Set(self, k, v):
    """Set one settings item.

    Args:
      k: str, name to set. The name will always be in lowercase.
      v: str, value to set.
    """
    self._CheckValidation(k, v)
    setattr(self._module, k.upper(), v)


class TestModuleSettings(ModuleSettings):  # pylint: disable=abstract-method
  """Settings that uses the test_settings module for storage."""

  def _LoadSettingsModule(self):
    """Load the test_settings module and return its name.

    Returns:
      str, fully qualified module name.
    Raises:
      ImportError: if the test_settings module could not be loaded.
    """
    try:
      # pylint: disable=g-importing-member
      # pylint: disable=g-import-not-at-top
      # pylint: disable=no-name-in-module
      from tests.simian import test_settings as unused_foo
    except ImportError:
      raise ImportError(
          'Missing test_settings, check dependencies')
    return 'tests.simian.test_settings'


class DictSettings(BaseSettings):
  """Settings that uses a dictionary for storage."""

  def _Initialize(self):
    self._settings = {}

  def _Get(self, k):
    """Get one settings item.

    Args:
      k: str, name to get. The name will always be in lowercase.
    Returns:
      any settings value
    Raises:
      AttributeError: if this settings item does not exist.
    """
    if k in self._settings:
      return self._settings[k]
    else:
      raise AttributeError(k)

  def _Set(self, k, v):
    """Set one settings item.

    Args:
      k: str, name to set. The name will always be in lowercase.
      v: str, value to set.
    """
    self._CheckValidation(k, v)
    self._settings[k] = v

  def _Dir(self):
    """Returns directory of all settings names as a list."""
    return self._settings.keys()


class SimianDictSettings(DictSettings):  # pylint: disable=abstract-method
  """Settings stored in a dictionary for Simian."""

  def _IsCaIdValid(self, _, v):
    """Is this settings ca_id value valid?

    Args:
      _: str, key being checked. See _VALIDATION_FUNC interface. Unused.
      v: unknown type (probably None or str), check this ca_id value.
    Returns:
      True if valid, False if not.
    """
    # TODO(user): Refactor. This regex is also @ simian/auth:util.CA_ID_RE
    return v is None or re.search(r'^[A-Z][0-9A-Z]+$', str(v)) is not None

  def _Initialize(self):
    """Initialize."""
    # We do this to initialize underlying DictSettings, nothing more:
    super(SimianDictSettings, self)._Initialize()
    mail_regex = (
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b')
    # Common settings
    self._SetValidation(
        'ca_public_cert_pem', self._VALIDATION_PEM_X509_CERT)
    self._SetValidation(
        'server_public_cert_pem', self._VALIDATION_PEM_X509_CERT)
    # Note: One should add other CA_ID based parameter validation here.

    # Client specific settings
    self._SetValidation('ca_id', self._VALIDATION_FUNC, self._IsCaIdValid)
    # Server specific settings
    self._SetValidation(
        'apple_auto_promote_enabled', self._VALIDATION_REGEX,
        r'^(True|False)$')
    self._SetValidation(
        'apple_auto_promote_stable_weekday', self._VALIDATION_REGEX,
        r'^[0-6]$')
    self._SetValidation(
        'apple_auto_unattended_enabled', self._VALIDATION_REGEX,
        r'^(True|False)$')
    self._SetValidation(
        'apple_unstable_grace_period_days', self._VALIDATION_REGEX,
        r'^[0-9]+$')
    self._SetValidation(
        'apple_testing_grace_period_days', self._VALIDATION_REGEX,
        r'^[0-9]+$')
    self._SetValidation(
        'email_admin_list', self._VALIDATION_REGEX,
        r'^%s' % mail_regex)
    self._SetValidation(
        'email_domain', self._VALIDATION_REGEX,
        r'^\w+(\.\w+)*(\.[a-z]{2,4})$')
    self._SetValidation(
        'email_on_every_change', self._VALIDATION_REGEX,
        r'^(True|False)$')
    self._SetValidation(
        'email_sender', self._VALIDATION_REGEX,
        r'^([\w ]+ <%s>|%s)$' % (mail_regex, mail_regex))
    self._SetValidation(
        'email_reply_to', self._VALIDATION_REGEX,
        r'^([\w ]+ <%s>|%s)$' % (mail_regex, mail_regex))
    self._SetValidation(
        'hour_start', self._VALIDATION_REGEX,
        r'^[0-9]+$')
    self._SetValidation(
        'hour_stop', self._VALIDATION_REGEX,
        r'^[0-9]+$')
    self._SetValidation(
        'uuid_lookup_url', self._VALIDATION_REGEX,
        r'^https?\:\/\/[a-zA-Z0-9\-\.]+(\.[a-zA-Z]{2,3})?(\/\S*)?$')
    self._SetValidation(
        'owner_lookup_url', self._VALIDATION_REGEX,
        r'^https?\:\/\/[a-zA-Z0-9\-\.]+(\.[a-zA-Z]{2,3})?(\/\S*)?$')
    self._SetValidation(
        'server_private_key_pem', self._VALIDATION_PEM_RSA_PRIVATE_KEY)


class FilesystemSettings(SimianDictSettings):
  """Settings that uses the filesystem for read-only storage."""

  _path = os.environ.get('SIMIAN_CONFIG_PATH') or '/etc/simian/'

  def _PopulateGlobals(self, set_func=None, globals_=None):
    """Populate global variables into the settings dict."""
    self._Set('server_port', 443)

  def _TranslateValue(self, value):
    """Translate incoming str value into other types.

    Args:
      value: str, e.g. 'hello' or '1' or 'True'
    Returns:
      e.g. (str)'hello', (int)1, (bool)True
    """
    try:
      i = int(value)
      return i
    except ValueError:
      pass

    if value.lower() in ['true', 'false']:
      return value.lower() == 'true'

    try:
      if value[0] == '\'' and value[-1] == '\'':
        value = value[1:-1]
      elif value[0] == '\"' and value[-1] == '\"':
        value = value[1:-1]
      elif value[0] == '[' and value[-1] == ']':
        value = re.split(r'\s*,\s*', value[1:-1])
    except IndexError:
      pass

    return value

  def _GetExternalConfiguration(
      self, name, default=None, path=None, as_file=False, open_=open,
      isdir_=os.path.isdir, join_=os.path.join):
    """Get configuration from external config files.

    Args:
      name: str, name of configuration file.
      default: object, default None, default value.
      path: str, default self.path, path to config file.
      as_file: bool, default False, if True read the entire file contents
        and return the contents as a string. If False, interpret the file
        as a config file per ConfigParser.
      open_: func, default open, function to open files with, for tests.
      isdir_: func, default os.path.isdir, for tests.
      join_: func, default os.path.join, for tests.
    Returns:
      if as_file=True, string contents of entire file.
      if as_file=False, dictionary of settings loaded from file.
    """
    logging.debug('_GetExternalConfiguration(%s)', name)
    if path is None:
      path = self._path

    config = {}

    if not isdir_(path):
      logging.error('Configuration directory not found: %s', path)
      value = None
    elif as_file:
      filepath = join_(path, name)
      try:
        f = open_(filepath, 'r')
        value = f.read()
        if value:
          value = value.strip()
        f.close()
      except IOError:
        value = None
    else:
      filepath = '%s.cfg' % join_(path, name)
      config = {}
      try:
        f = open_(filepath, 'r')
        cp = ConfigParser.ConfigParser()
        cp.readfp(f)
        f.close()
        for i, v in cp.items('settings'):
          config[i] = self._TranslateValue(v)
        value = config
      except (IOError, ConfigParser.Error):
        value = None

    if value is None:
      value = default

    if value is None:
      logging.error('Configuration not found: %s', name)

    return value

  def _GetExternalPem(self, k):
    """Get an external PEM value from config.

    Args:
      k: str, name to retrieve.
    Returns:
      value
    Raises:
      AttributeError: if the name does not exist in external settings.
    """
    logging.debug('_GetExternalPem(%s)', k)
    if k in self._settings:
      return self._settings[k]
    pem_file = '%s.pem' % k[:-4]
    path = os.path.join(self._path, 'ssl')
    pem = self._GetExternalConfiguration(pem_file, as_file=True, path=path)
    if pem:
      self._settings[k] = pem
    else:
      raise AttributeError(k)
    return pem

  def _GetExternalValue(self, k):
    """Get an external name/value from config.

    Args:
      k: str, name to retrieve.
    Returns:
      value
    Raises:
      AttributeError: if the name does not exist in external settings.
    """
    logging.debug('_GetExternalValue(%s)', k)
    if k in self._settings:
      return self._settings[k]
    config = self._GetExternalConfiguration('settings')
    if config is not None:
      for j in config:
        self._settings[j] = config[j]
      if k not in self._settings:
        raise AttributeError(k)
    else:
      raise AttributeError(k)
    return self._settings[k]

  def _Get(self, k):
    """Get one settings item.

    Args:
      k: str, name to get. The name will always be in lowercase.
    Returns:
      any settings value
    Raises:
      AttributeError: if this settings item does not exist.
    """
    # oss config have domain/subdomain instead of server_hostname
    if k == 'server_hostname':
      try:
        return self._GetExternalValue(k)
      except AttributeError:
        return '%s.%s' % (
            self._GetExternalValue('subdomain'),
            self._GetExternalValue('domain')
        )
    logging.debug('_Get(%s)', k)
    if k.endswith('_pem'):
      v = self._GetExternalPem(k)
    else:
      v = self._GetExternalValue(k)

    return v

  def _Dir(self):
    """Returns directory of all settings names as a list.

    Raises:
      NotImplementedError: if this method is not implemented.
    """
    raise NotImplementedError


class DatastoreSettings(SimianDictSettings):
  """Settings stored in GAE datastore and dictionary.

  All globals are loaded into the dictionary storage, but not _Set() into
  the datastore.

  All future _Get() operations check both the dictionary and datastore.
  All future _Set() operations only affect the datastore.
  """

  def _Initialize(self):
    SimianDictSettings._Initialize(self)

    self._module.models = importlib.import_module(
        'simian.mac.models')

  def _PopulateGlobals(self, set_func=None, globals_=None):
    """Populate global variables into the settings dict."""
    # Populate the global variables into the dictionary backed settings via
    # this specific set_func. Without this specific usage the global settings
    # would be populated back into datastore via _Set() calls.
    # pylint: disable=protected-access
    set_func = lambda k, v: DictSettings._Set(self, k, v)
    DictSettings._PopulateGlobals(self, set_func=set_func, globals_=globals_)

  def _Get(self, k):
    """Get one settings item.

    Args:
      k: str, name to get. The name will always be in lowercase.
    Returns:
      any settings value
    Raises:
      AttributeError: if this settings item does not exist.
    """
    # Try the dictionary of settings first.
    try:
      v = DictSettings._Get(self, k)  # pylint: disable=protected-access
      return v
    except AttributeError:
      pass  # Not a problem, keep trying.

    item, unused_mtime = self._module.models.Settings.GetItem(k)
    if item is None:
      raise AttributeError(k)
    return item

  def _Set(self, k, v):
    """Set one settings item.

    Args:
      k: str, name to set. The name will always be in lowercase.
      v: str, value to set.
    """
    self._CheckValidation(k, v)
    self._module.models.Settings.SetItem(k, v)

  def _Dir(self):
    """Returns directory of all settings names as a list.

    Returns:
      list of all settings names.
    Raises:
      NotImplementedError: if this method is not implemented.
    """
    a = self._module.models.Settings.GetAll()
    return list(set(DictSettings._Dir(self) + [x for x in a]))  # pylint: disable=protected-access


def Setup():
  if __name__ != '__main__':
    if not hasattr(sys.modules[__name__], 'is_class'):
      settings_class = None

      if GAE:
        settings_class = DatastoreSettings
      elif DEV_APPSERVER:
        settings_class = DatastoreSettings
      elif TESTING:
        if not SETTINGS_TESTING:
          settings_class = TestModuleSettings
      else:
        settings_class = FilesystemSettings

      if settings_class is not None:
        sys.modules[__name__] = settings_class(sys.modules[__name__])


Setup()
