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

"""Configurable settings module."""



import ConfigParser
import logging
import os
import re

try:
  from simian.mac import models
except (ImportError, AttributeError):
  # ImportError: import failed
  # AttributeError: the App Engine db modules are there but un-configured,
  #  meaning we are running on the PAR client.
  pass


# Path for configuration options
CONFIG_PATH = '/etc/simian/'
# Cached version of CONFIG_PATH/simian.cfg
_config = None


def GetExternalConfiguration(name, as_file=False, _open=open):
  """Gets an external configuration value for a given name.

  If this code is being executed from App Engine, the configuration will be
  loaded from Datastore/memcache.

  If it's run elsewhere, it will be loaded from a file named
  /etc/simian/<name> if as_file=True, otherwise from a settings value from
  /etc/simian/simian.cfg.

  Args:
    name: str, name of the configuration to get.
    as_file: bool, whether to read from separate file, or settings file
    _open: method, to open a file.
  Returns:
    str configuration value, or None if the configuration doesn't exist.
  """
  global _config

  if 'SERVER_SOFTWARE' in os.environ:  # running on App Engine.
    try:
      value = models.KeyValueCache.MemcacheWrappedGet(
          name, prop_name='text_value')
    except models.db.Error:
      value = None
  else:
    if not os.path.isdir(CONFIG_PATH):
      logging.error('Configuration directory not found: %s' % CONFIG_PATH)
      return

    if as_file:
      filepath = os.path.join(CONFIG_PATH, name)
      try:
        f = _open(filepath, 'r')
        value = f.read()
        value = value.strip()
        f.close()
      except IOError:
        value = None
    else:
      if _config is None:
        filepath = os.path.join(CONFIG_PATH, 'simian.cfg')
        try:
          f = _open(filepath, 'r')
          cp = ConfigParser.ConfigParser()
          cp.readfp(f)
          f.close()
          _config = cp
          value = cp.get('config', name)
        except (IOError, ConfigParser.Error):
          value = None
      else:
        try:
          value = _config.get('config', name)
        except ConfigParser.Error:
          value = None

  if value is None:
    logging.error('Configuration not found: %s', name)

  return value


SUBDOMAIN = GetExternalConfiguration('subdomain')
DOMAIN = GetExternalConfiguration('domain')

SERVER_HOSTNAME = '%s.%s' % (SUBDOMAIN, DOMAIN)
SERVER_HOSTNAME_REGEX = re.compile(
    '^((\w+)\.latest\.)?%s\.%s$' % (SUBDOMAIN, DOMAIN))
SERVER_PORT = 443

ADMINS = GetExternalConfiguration('admins')

UUID_LOOKUP_URL = GetExternalConfiguration('uuid_lookup_url')
OWNER_LOOKUP_URL = GetExternalConfiguration('owner_lookup_url')


CA_PUBLIC_CERT_PEM = GetExternalConfiguration(
    'ca_public_cert.pem', as_file=True)
SERVER_PUBLIC_CERT_PEM = GetExternalConfiguration(
    'server_public_cert.pem', as_file=True)
ROOT_CA_CERT_CHAIN_PEM = GetExternalConfiguration(
    'root_ca_cert_chain.pem', as_file=True)
REQUIRED_ISSUER = GetExternalConfiguration('required_issuer')
ROOT_CA_CERT_CHAIN_PEM = GetExternalConfiguration(
    'root_ca_cert_chain.pem', as_file=True)
CLIENT_SSL_PATH = GetExternalConfiguration('client_ssl_path')


EMAIL_DOMAIN = GetExternalConfiguration('email_domain')
EMAIL_SENDER = GetExternalConfiguration('email_sender')
EMAIL_REPLY_TO = GetExternalConfiguration('email_reply_to')
# subject must contain exactly one "%s" for hostname concatenation
WELCOME_EMAIL_SUBJECT = GetExternalConfiguration(
    'welcome_email_subject')
WELCOME_EMAIL_BODY = GetExternalConfiguration('welcome_email_body')