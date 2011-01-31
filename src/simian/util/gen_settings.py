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
import os
import os.path
import re
import sys


MULTICONFIG_FILE = 'simian.cfg'


class Error(Exception):
  pass


class SettingsCodeGenerator(object):
  def __init__(self, config_dir):
    """Init.

    Args:
      config_dir: str, path to load config from
    """
    self.config_dir = config_dir
    self.config = {}

  def LoadSettingsFile(self, name, _open=open):
    """Load settings file for name.

    Args:
      name: str, like "ca.pem"
      _open: func, optional, to open() file with
    """
    filepath = os.path.join(self.config_dir, name)
    f = _open(filepath, 'r')
    value = f.read()
    f.close()
    name = name.replace('.', '_')  # names like FOO_PEM not FOO.PEM
    self.config[name] = value

  def LoadAllSettingsFiles(self):
    """Load all settings files."""
    d = os.listdir(self.config_dir)
    for i in d:
      if i.startswith('.'):  # skip dot files, like .DS_Store
        continue
      if os.path.isfile(
          os.path.join(self.config_dir, i)) and i != MULTICONFIG_FILE:
        self.LoadSettingsFile(i)

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

    if value in ['True', 'False']:
      return value == 'True'

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

  def LoadMultiSettingsFile(self, _open=open):
    """Load the multi settings file e.g. simian.cfg.

    Args:
      _open: func, optional, to open() file with
    """
    filepath = os.path.join(self.config_dir, MULTICONFIG_FILE)
    f = _open(filepath, 'r')
    cp = ConfigParser.ConfigParser()
    cp.readfp(f)
    f.close()
    for name, value in cp.items('config'):
      value = self._TranslateValue(value)
      self.config[name] = value

  def LoadAllSettings(self):
    """Load all settings files."""
    self.config = {}
    self.LoadMultiSettingsFile()
    self.LoadAllSettingsFiles()

  def _OrderedKeys(self):
    """Returns ordered list of config keys."""
    k1 = []
    k2 = []
    for name in self.config.keys():
      v = self.config.get(name, '')
      if type(v) is str and v.find('\n') > -1:
        k2.append(name)
      else:
        k1.append(name)
    k1.sort()
    k2.sort()
    k1.extend(k2)
    return k1

  def _FormatName(self, name):
    """Format a name for output.

    Args:
      name: str, like 'ca_public_cert.pem'
    Returns:
      str like 'CA_PUBLIC_CERT_PEM'
    """
    name = name.replace('.', '_')
    name = name.upper()
    return name

  def _FormatValue(self, value):
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
        fv = self._FormatValue(i)
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
    else:
      output.append(str(value))
    return output

  def GenerateName(self, name):
    """Generate output for one config name.

    Args:
      name: str, like 'CA_PUBLIC_CERT_PEM'
    Returns:
      list in output format, e.g. ['name = VALUE' , ... ]
    """
    output = []
    format_name = self._FormatName(name)
    format_value = self._FormatValue(self.config.get(name, None))
    format_value[0] = '%s = %s' % (format_name, format_value[0])
    return format_value

  def Generate(self):
    """Generate all output.

    Returns:
      list in output format
    """
    self.LoadAllSettings()

    output = []
    output.append('#!/usr/bin/python')
    output.append('# Generated settings')
    output.append('')

    order_k = self._OrderedKeys()
    for k in order_k:
      output.extend(self.GenerateName(k))
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
    opts: dict, of options to run
  """
  kwargs = {}

  if 'config-dir' in opts:
    kwargs['config_dir'] = opts['config-dir']

  scg = SettingsCodeGenerator(**kwargs)

  if 'output' in opts:
    scg.Write(opts['output'])
  else:
    scg.WriteFp(sys.stdout)


def Usage(argv):
  """Print usage information.

  Args:
    argv: list, of arguments
  """
  print >>sys.stderr, """%s [--config-dir path_to_config] [--output filename]

--config-dir path_to_config:  point to config residing at path_to_config

--output filename:  output to filename instead of stdout
""" % argv[0]


def main(argv):
  optsd, unused = getopt.gnu_getopt(
      argv, 'c:o:h', ['config-dir=', 'output=', 'help'])

  opts = {}
  for optk, optv in optsd:
    if optk in ['c', '--config-dir']:
      opts['config-dir'] = optv
    elif optk in ['o', '--output']:
      opts['output'] = optv
    elif optk in ['h', '--help']:
      opts['help'] = True

  if 'help' in opts:
    return Usage(argv)
  else:
    return Run(opts)


if __name__ == '__main__':
  main(sys.argv)
