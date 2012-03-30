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

"""Simian Settings Models."""




import logging

from google.appengine.ext import db

from simian.mac.models import base

SETTINGS = {
    'api_info_key': {
        'type': 'random_str',
        'title': 'API Info Key',
    },
    'email_domain': {
        'type': 'string',
        'title': 'Email Domain',
    },
    'email_sender': {
        'type': 'string',
        'title': 'Email Sender',
        'comment': 'e.g. Simian Team <admin@example.com>',
    },
    'email_reply_to': {
        'type': 'string',
        'title': 'Email reply-to',
        'comment': 'e.g. Simian Team <admin@example.com>',
    },
    'uuid_lookup_url': {
        'type': 'string',
        'title': 'UUID lookup tool URL',
        'comment': 'uuid will be appended to URL like http://corp/<uuid>',
    },
    'owner_lookup_url': {
        'type': 'string',
        'title': 'Owner lookup tool URL',
        'comment': ('owner username will be appended to URL like '
                    'http://corp/<owner-username>'),
    },
    'required_issuer': {
        'type': 'string',
        'title': 'Required Issuer',
    },
    'xsrf_secret': {
        'type': 'random_str',
        'title': 'XSRF secret',
    },
    'server_private_key_pem': {
        'type': 'pem',
    },
    'server_public_cert_pem': {
        'type': 'pem',
    },
    'ca_public_cert_pem': {
        'type': 'pem',
    }
}


class Settings(base.KeyValueCache):
  """Model for settings."""

  @classmethod
  def GetItem(cls, name):
    if SETTINGS.get(name, {}).get('type') in ['pem', 'string', 'random_str']:
      value, mtime = super(Settings, cls).GetItem(name)
    else:
      value, mtime = cls.GetSerializedItem(name)
    return value, mtime

  @classmethod
  def SetItem(cls, name, value):
    if SETTINGS.get(name, {}).get('type') in ['pem', 'string', 'random_str']:
      return super(Settings, cls).SetItem(name, value)
    else:
      return cls.SetSerializedItem(name, value)

  @classmethod
  def GetAll(cls):
    settings = SETTINGS.copy()
    for setting in SETTINGS:
      value, mtime = cls.GetItem(setting)
      settings[setting]['value'] = value
      settings[setting]['mtime'] = mtime
    return settings