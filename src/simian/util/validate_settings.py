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
"""Tool to validate settings."""

import logging
import os
import sys


SIMIAN_CONFIG_PATH = None


def ErrorExit(msg, *args):
  logging.error(msg, *args)
  sys.exit(1)


def ValidatePem(arg, dirname, fnames):
  """Validate all fnames found in dirname as PEM files.

  Args:
    arg: tuple, (settings module to make use of for validation, str of
        pem content type to look for "cert" or "key")
    dirname: str, directory name
    fnames: list, of files names relative to dirname
  """
  settings, pem_content = arg
  logging.info('Validating pem inside %s', dirname)
  i = 0
  while i < len(fnames):
    fname = fnames[i]
    fname_full = os.path.join(dirname, fname)
    if not os.path.exists(fname_full):
      ErrorExit('Does not exist: %s', fname_full)
    if fname.startswith('.'):
      del(fnames[i])  # if this is a directory, this stops recursion into it
      continue
    if not os.path.isfile(fname_full):
      ErrorExit('Not a file, remove: %s', fname_full)
    if not fname_full.endswith('.pem'):
      ErrorExit('File without .pem extension found, remove: %s', fname_full)
    try:
      f = open(fname_full, 'r')
      s = f.read()
      f.close()
    except IOError, e:
      ErrorExit('IO error: %s, %s', fname_full, str(e))

    try:
      logging.info('Validating %s', fname_full)
      if pem_content == 'cert':
        settings.CheckValuePemX509Cert('server_public_cert_pem', s)
      elif pem_content == 'key':
        settings.CheckValuePemRsaPrivateKey('server_private_cert_pem', s)
      logging.info('Validated %s', fname_full)
    except ValueError, e:
      ErrorExit('Error reading %s: %s', fname_full, str(e))

    i += 1


def FindPemAndValidate(settings):
  """Find all PEM files located in the filesystem ssl dirs, validate them.

  Args:
    settings: settings module to make use of for validation.
  """
  ssl_path = os.path.join(SIMIAN_CONFIG_PATH, 'ssl')

  os.path.walk(
      os.path.join(ssl_path, 'certs'), ValidatePem, (settings, 'cert'))
  os.path.walk(
      os.path.join(ssl_path, 'private_keys'), ValidatePem, (settings, 'key'))

  d = {}

  def _GrabTopSslDir(arg, dirname, fnames):
    d = arg[0]
    if dirname == ssl_path:
      if 'certs' in fnames:
        fnames.remove('certs')
      if 'private_keys' in fnames:
        fnames.remove('private_keys')
      d['dirname'] = dirname
      d['fnames'] = fnames

  os.path.walk(ssl_path, _GrabTopSslDir, (d, ))

  if d['dirname']:
    ValidatePem((settings, 'cert'), d['dirname'], d['fnames'])

def Validate():
  logging.info('Loading settings')

  try:
    from simian import settings
  except Exception, e:
    ErrorExit('Error: %s', str(e))

  if not settings:
    ErrorExit('%s/settings.cfg is missing or empty', SIMIAN_CONFIG_PATH)

  required_settings = [
      'server_public_cert_pem',
      'ca_public_cert_pem',
      'required_issuer',
      'domain',
      'subdomain',
      'auth_domain',
  ]

  for k in required_settings:
    logging.info('Looking for required setting %s', k)
    if not hasattr(settings, k):
      ErrorExit('missing required setting %s', k)
    else:
      logging.info('%s = %s', k, getattr(settings, k))

  logging.info('Validating settings that exist')

  settings.CheckValidation()

  logging.info('Checking domain & subdomain')

  if settings.DOMAIN == 'example' and settings.SUBDOMAIN == 'appspot.com':
    ErrorExit('configure domain value')

  logging.info('Validating pem files found in ssl dir')

  FindPemAndValidate(settings)


def main(argv):
  global SIMIAN_CONFIG_PATH

  logging.getLogger().setLevel(logging.DEBUG)

  SIMIAN_CONFIG_PATH = sys.argv[1]
  os.environ['SIMIAN_CONFIG_PATH'] = SIMIAN_CONFIG_PATH
  for path in sys.argv[2:]:
    sys.path.append(path)
  Validate()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
