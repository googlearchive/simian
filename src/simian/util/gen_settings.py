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

"""Tool to convert live settings into canned Python settings code."""



import ConfigParser
import getopt
import inspect
import os
import os.path
import re
import sys


class Error(Exception):
  """Base error."""


class ConfigError(Error):
  """Error in the config values."""


class UsageError(Error):
  """Error in usage of the client from cli."""


EXTERNAL_CONFIG_SECTION_SUFFIX = '_extconfig'
CONFIG_TYPE_CLIENT = 'client'
CONFIG_TYPE_SERVER = 'server'
CONFIG_TYPES = [CONFIG_TYPE_CLIENT, CONFIG_TYPE_SERVER]
REQUIRED = 'required'
CONFIG_NAME_ALWAYS_STATIC = ['config_path', 'client_ssl_path']
GET_EXTERNAL_CONFIG = {}
CONFIG_NAME_VALIDATION = {
  'subdomain': {
    REQUIRED: CONFIG_TYPES,
  },
  'domain': {
    REQUIRED: CONFIG_TYPES,
  },
  'required_issuer': {
    REQUIRED: CONFIG_TYPES,
  },
  'ca_public_cert_pem': {
    REQUIRED: CONFIG_TYPES,
  },
  'server_public_cert_pem': {
    REQUIRED: CONFIG_TYPES,
  },
  'client_ssl_path': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'config_path': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'applesus': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'certname': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'primary_user': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'hostname': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'configtrack': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'simiantrack': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'site': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'location': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'root_ca_cert_chain_pem': {
    REQUIRED: [CONFIG_TYPE_CLIENT],
  },
  'uuid_lookup_url': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'owner_lookup_url': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'email_domain': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'email_sender': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'email_reply_to': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'send_welcome_emails': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'welcome_email_subject': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'welcome_email_body': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'email_admin_list': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'admins': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'security_users': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'support_users': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
  'api_info_key': {
      REQUIRED: [CONFIG_TYPE_SERVER],
  },
}

GET_EXTERNAL_CONFIG[CONFIG_TYPE_CLIENT] = """
import os
import ConfigParser

def GetExternalConfiguration(
    name, default=None, path=None, as_file=False, open_=open):
  global _config

  if path is None:
    path = CONFIG_PATH

  if not os.path.isdir(path):
    logging.error('Configuration directory not found: %s' % path)
    value = None
  elif as_file:
    filepath = os.path.join(path, name)
    try:
      f = open_(filepath, 'r')
      value = f.read()
      value = value.strip()
      f.close()
      if _config is None:
        _config = {}
      _config[name] = value
    except IOError:
      value = None
  else:
    if _config is None:
      _config = {}
      for config_type in ['common', 'client']:
        filepath = '%s.cfg' % os.path.join(path, config_type)
        try:
          f = open_(filepath, 'r')
          cp = ConfigParser.ConfigParser()
          cp.readfp(f)
          f.close()
          for i, v in cp.items(config_type):
            _config[i] = TranslateValue(v)
        except (IOError, ConfigParser.Error):
          pass
    value = _config.get(name, None)

  if value is None:
    value = default

  if value is None:
    logging.error('Configuration not found: %s', name)

  return value
"""

GET_EXTERNAL_CONFIG[CONFIG_TYPE_SERVER] = """
from simian.mac import models

def GetExternalConfiguration(name, default=None):
  global _config

  if models:
    try:
      value = models.KeyValueCache.MemcacheWrappedGet(
          name, prop_name='text_value')
    except models.db.Error:
      value = None
  else:
    value = None

  if value is None:
    value = default

  if value is None:
    logging.error('Configuration not found: %s', name)

  return value
"""


def TranslateValue(value):
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


def FormatName(name):
  """Format a name for output.

  Args:
    name: str, like 'ca_public_cert.pem'
  Returns:
    str like 'CA_PUBLIC_CERT_PEM'
  """
  name = name.replace('.', '_')
  name = name.upper()
  return name


def FormatValue(value):
  """Format a value for output.

  Args:
    value: some value, e.g. [1,2,3]
  Returns:
    list in output format, e.g. ['[1,2,3]']
  """
  output = []
  if type(value) is str:
    if value.find('\n') > -1:
      for line in value.split('\n'):
        if not output:
          output.append('\"\"\"%s' % line)
        else:
          output.append(line)
      output[-1] = '%s\"\"\"' % output[-1]
    else:
      output.append('\'%s\'' % value)
  elif type(value) in (list, tuple):
    tmp_output = []
    tmp_value_output = []

    for i in value:
      fv = FormatValue(i)
      if len(fv) == 1:
        tmp_value_output.append(fv[0])
      elif len(fv) > 0:
        if len(tmp_value_output):
          tmp_output.append(', '.join(tmp_value_output))
        tmp_value_output = []
        for j in xrange(len(fv)):
          if j > 0 and j == len(fv) - 1:
            tmp_value_output.append(str(fv[j]))
          else:
            tmp_output.append(str(fv[j]))

    if len(tmp_value_output):
      tmp_output.append(', '.join(tmp_value_output))

    if len(tmp_output) > 1:
      for i in xrange(len(tmp_output)):
        if i == 0:
          output.append('[%s' % tmp_output[i])
        else:
          output.append(tmp_output[i])
        if i == len(tmp_output) - 1:
          output[-1] = '%s]' % output[-1]
    elif len(tmp_output) == 1:
      output.append('[%s]' % tmp_output[0])
  elif issubclass(value.__class__, WrappedValue):
    output.append(value())
  else:
    output.append(str(value))
  return output


class WrappedValue(object):
  """Class representing values which generate custom output when called."""

  def __init__(self, name, default_value, config_type):
    self.name = name
    self.default_value = default_value
    self.config_type = config_type

  def __str__(self):
    return str(self.default_value)


class RegexCompile(WrappedValue):
  """Class representing a regex to re.compile."""

  def __call__(self):
    return ('re.compile(\n'
            '    r\'%s\')' % self.default_value)


class ExternalConfiguration(WrappedValue):
  """Class representing a value loaded from external config."""

  def __call__(self):
    return ('GetExternalConfiguration(\n'
            '    \'%s\',\n'
            '    %s)' % (
                self.name, FormatValue(self.default_value)[0]))


class ExternalPemConfiguration(ExternalConfiguration):
  """Class representing a PEM loaded from external config."""

  def __init__(self, *args, **kwargs):
    super(ExternalPemConfiguration, self).__init__(*args, **kwargs)
    self.name = self.name.replace('_pem', '.pem')

  def __call__(self):
    if self.config_type == CONFIG_TYPE_CLIENT:
      return ('GetExternalConfiguration(\n'
              '    \'%s\',\n'
              '    %s,\n'
              '    path=CLIENT_SSL_PATH, as_file=True)' % (
                  self.name, FormatValue(self.default_value)[0]))
    else:
      return ('GetExternalConfiguration(\n'
              '    \'%s\',\n'
              '    %s)' % (
                  self.name, FormatValue(self.default_value)[0]))


class SettingsCodeGenerator(object):
  """Generator for settings as python code from config files."""

  def __init__(self, config_type):
    """Init.

    Args:
      config_type: str, like "client" or "server"
    """
    self.config_type = config_type
    self.config = {}

  def _OrderedKeys(self):
    """Returns ordered list of config keys."""
    k1 = []
    k2 = []
    for name in self.config.keys():
      v = self.config.get(name, '')
      if type(v) is str and name in CONFIG_NAME_ALWAYS_STATIC:
        k1.append(name)
      else:
        k2.append(name)
    k1.sort()
    k2.sort()
    k1.extend(k2)
    return k1

  def _GenerateName(self, name):
    """Generate output for one config name.

    Args:
      name: str, like 'CA_PUBLIC_CERT_PEM'
    Returns:
      list in output format, e.g. ['name = VALUE' , ... ]
    """
    output = []
    format_name = FormatName(name)
    format_value = FormatValue(self.config.get(name, None))
    format_value[0] = '%s = %s' % (format_name, format_value[0])
    return format_value

  def LoadConfigFile(self, filepath, open_=open):
    """Load config file.

    Args:
      filepath: str, filepath of config file to load
      open_: func, optional, to open() file with
    Returns:
      ConfigParser instance
    """
    f = open_(filepath, 'r')
    cp = ConfigParser.ConfigParser()
    cp.readfp(f)
    f.close()
    return cp

  def LoadConfigFiles(self, config_files):
    """Load config files.

    Args:
      config_files: list, of filepaths to load
    """
    self.config = {}
    extconfig = '%s%s' % (self.config_type, EXTERNAL_CONFIG_SECTION_SUFFIX)

    for filepath in config_files:
      cp = self.LoadConfigFile(filepath)
      for section in [
          self.config_type, extconfig,
          'common', 'common%s' % EXTERNAL_CONFIG_SECTION_SUFFIX]:
        if cp.has_section(section):
          for name, value in cp.items(section):
            value = TranslateValue(value)
            if (name not in CONFIG_NAME_ALWAYS_STATIC and (
                section.endswith(EXTERNAL_CONFIG_SECTION_SUFFIX) or
                self.config_type == CONFIG_TYPE_CLIENT)):
              if name.endswith('_pem'):
                value = ExternalPemConfiguration(
                    name, value, config_type=self.config_type)
              else:
                value = ExternalConfiguration(
                    name, value, config_type=self.config_type)
              self.config[name] = value
            else:
              self.config[name] = value

  def ValidateConfig(self):
    """Validate the loaded config.

    Raises:
      ConfigError: the config has errors in it
    """
    if not self.config:
      raise ConfigError('no config')

    for name in CONFIG_NAME_VALIDATION:
      if REQUIRED in CONFIG_NAME_VALIDATION[name]:
        if self.config_type in CONFIG_NAME_VALIDATION[name][REQUIRED]:
          if name not in self.config:
            raise ConfigError('missing config value \"%s\"' % name)
      if name not in CONFIG_NAME_VALIDATION:
        raise ConfigError('unknown config value \"%s\"' % name)

  def ComputeConfig(self):
    """Compute config values from those already loaded.

    Raises:
      ConfigError: the config has errors in it
    """
    if not self.config:
      raise ConfigError('no config')

    self.config['server_hostname'] = '%s.%s' % (
        self.config['subdomain'],
        self.config['domain'])
    if self.config_type == CONFIG_TYPE_CLIENT:
      self.config['server_hostname_regex'] = RegexCompile(
          'server_hostname_regex',
          '^((\w+)\.latest\.)?%s\.%s$' % (
              self.config['subdomain'], self.config['domain']),
          self.config_type)
      self.config['server_port'] = 443

  def Generate(self):
    """Generate all output.

    Returns:
      list in output format
    """
    if not self.config:
      return

    try:
      translate_value = inspect.getsourcelines(TranslateValue)[0]
      for i in xrange(len(translate_value)):
        if translate_value[i][-1] == '\n':
          translate_value[i] = translate_value[i][0:-1]

    except IOError, e:
      raise Error(str(e))  # could not find TranslateValue function

    output = []
    output.append('#!/usr/bin/python')
    output.append('# Generated settings')
    output.append('# config type: %s' % self.config_type)
    output.append('import re')
    output.append('import logging')
    output.append('')
    output.append('_config = None')
    output.append('')
    output.extend(translate_value)
    output.append('')
    output.append('####')
    output.append(GET_EXTERNAL_CONFIG[self.config_type])
    output.append('####')

    order_k = self._OrderedKeys()
    for k in order_k:
      output.extend(self._GenerateName(k))
      output.append('')

    return output

  def WriteFp(self, fp):
    """Generate and write to a file.

    Args:
      fp: file-like object
    """
    fp.write('\n'.join(self.Generate()))

  def Write(self, filename):
    """Generate and write to a filename.

    Args:
      filename: str, like 'foo.py'
    """
    f = open(filename, 'w')
    self.WriteFp(f)
    f.close()


def Run(opts):
  """Run gen_settings with options.

  Args:
    opts: dict, of options to run with
  Returns:
    int, exit status
  """
  scg = SettingsCodeGenerator(config_type=opts['config_type'])
  scg.LoadConfigFiles(opts['config_files'])
  scg.ValidateConfig()
  scg.ComputeConfig()

  if 'output' in opts:
    scg.Write(opts['output'])
  else:
    scg.WriteFp(sys.stdout)

  return 0


def Usage(argv):
  """Print usage information.

  Args:
    argv: list, of arguments
  Returns:
    int, exit status
  """
  print >>sys.stderr, """

%s [-t type] [-o file.py] [config files ...]

-t [client|server]:  what type of config file to output

-o [path]:           where to output settings python

""" % argv[0]
  return 1


def RunArgv(argv):
  """Parse argv and return options.

  Args:
    argv: list, of arguments
  Returns:
    int, exit status
  """
  optsd, config_files = getopt.gnu_getopt(
      argv, 't:o:h', [])

  try:
    opts = {}
    for optk, optv in optsd:
      if optk in ['-t']:
        if optv in CONFIG_TYPES:
          opts['config_type'] = optv
        else:
          raise UsageError('-t must be one of %s' % CONFIG_TYPES)
      elif optk in ['-o']:
        opts['output'] = optv
      elif optk in ['-h']:
        opts['help'] = True
    opts['config_files'] = config_files[1:]

    usage = ('help' in opts or
        not opts.get('config_files') or not opts.get('config_type'))
  except ConfigError, e:
    print e.args[0]
    usage = True

  try:
    if usage:
      return Usage(argv)
    else:
      return Run(opts)
  except Error, e:
    print >>sys.stderr, e.args[0]
    return 1


def main(argv):
  return RunArgv(argv)


if __name__ == '__main__':
  sys.exit(main(sys.argv))