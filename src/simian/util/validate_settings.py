#!/usr/bin/env python
# 
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Tool to validate settings."""



import logging
import os
import sys


SIMIAN_CONFIG_PATH = None


def ErrorExit(msg, *args):
  logging.error(msg, *args)
  sys.exit(1)


def ValidatePem(arg, dirname, fnames):
  settings, pem_content = arg
  logging.info('Validating pem inside %s', dirname)
  for fname in fnames:
    fname_full = os.path.join(dirname, fname)
    f = open(fname_full, 'r')
    s = f.read()
    f.close()
    try:
      logging.info('Validating %s', fname_full)
      if pem_content == 'cert':
        settings.CheckValuePemX509Cert('server_public_cert_pem', s)
      elif pem_content == 'key':
        settings.CheckValuePemRsaPrivateKey('server_private_cert_pem', s)
      logging.info('Validated %s', fname_full)
    except ValueError, e:
      ErrorExit('Error reading %s: %s', fname_full, str(e))
      
  
def FindPemAndValidate(settings):
  os.path.walk(
      os.path.join(SIMIAN_CONFIG_PATH, 'ssl', 'certs'), 
      ValidatePem, (settings, 'cert'))
  os.path.walk(
      os.path.join(SIMIAN_CONFIG_PATH, 'ssl', 'private_keys'), 
      ValidatePem, (settings, 'key'))


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
  