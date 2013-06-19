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
    'apple_auto_promote_enabled': {
        'type': 'bool',
        'title': 'Apple Update Auto-Promotion Enabled',
        'comment': 'If enabled, items auto-promote through release tracks.',
        'default': True,
    },
    'apple_auto_promote_stable_weekday': {
        'type': 'integer',
        'title': 'Apple Update Stable Auto-Promote Weekday',
        'comment': 'Integer weekday, where Monday is 0 and Sunday is 6.',
        'default': 2,
    },
    'apple_auto_unattended_enabled': {
        'type': 'bool',
        'title': 'Apple Update Auto-Unattended Enabled',
        'comment': ('If enabled, new updates not requiring a restart are set '
                    'as unattended automatically.'),
        'default': True,
    },
    'apple_unstable_grace_period_days': {
        'type': 'integer',
        'title': 'Apple Update Auto-Promote Unstable Grace Period Days',
        'comment': ('Number of days before updates auto-promote from '
                    'unstable to testing.'),
        'default': 4,
    },
    'apple_testing_grace_period_days': {
        'type': 'integer',
        'title': 'Apple Update Auto-Promote Testing Grace Period Days',
        'comment': ('Number of days before updates auto-promote from '
                    'testing to stable.'),
        'default': 7,
    },
    'email_admin_list': {
        'type': 'string',
        'title': 'Admin List Email',
        'comment': 'Server notifications are emailed to this address',
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
    'email_on_every_change': {
        'type': 'bool',
        'title': 'Notify Admins of all changes.',
        'comment': 'Check to send a mail to all admins on every change.',
        'default': False,
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
        'suffix': True,
    },
    'xsrf_secret': {
        'type': 'random_str',
        'title': 'XSRF secret',
    },
    'server_private_key_pem': {
        'type': 'pem',
        'suffix': True,
    },
    'server_public_cert_pem': {
        'type': 'pem',
        'suffix': True,
    },
    'ca_public_cert_pem': {
        'type': 'pem',
        'suffix': True,
    }
}


class Settings(base.KeyValueCache):
  """Model for settings."""

  @classmethod
  def GetType(cls, name):
    """Get the type for a setting.

    Args:
      name: str, like 'ca_public_cert_pem' or 'suffix_ca_public_cert_pem'
          if suffix==True in the SETTINGS[name] dict above.
    Returns:
      type like 'pem', 'string', 'random_str', None
    """
    if name in SETTINGS:
      return SETTINGS.get(name, {}).get('type')
    # Look for name as a prefix to a setting with suffix==True.
    for k in SETTINGS:
      if ('suffix' in SETTINGS[k] and SETTINGS[k]['suffix'] and
          name.endswith('_%s' % k)):
        return SETTINGS.get(k, {}).get('type')
    return None

  @classmethod
  def GetItem(cls, name):
    """Get an item from settings.

    If the item is in a serialized container it will be deserialized
    before returning it.

    Args:
      name: str, like 'ca_public_cert_pem' or 'required_issuer'
    Returns:
      (value for that setting, datetime time of last change)
    """
    if Settings.GetType(name) in ['pem', 'string', 'random_str']:
      value, mtime = super(Settings, cls).GetItem(name)
    else:
      value, mtime = cls.GetSerializedItem(name)

    if mtime is None:  # item was not in Datastore, use default if it exists.
      value = SETTINGS.get(name, {}).get('default')
    return value, mtime

  @classmethod
  def SetItem(cls, name, value):
    """Set an item into settings.

    If the item belongs in a serialized container it will be serialized
    before storage.

    Args:
      name: str, like 'ca_public_cert_pem'
      value: str, value
    """
    if Settings.GetType(name) in ['pem', 'string', 'random_str']:
      return super(Settings, cls).SetItem(name, value)
    else:
      return cls.SetSerializedItem(name, value)

  @classmethod
  def GetAll(cls):
    """Return a dictionary of all settings.

    Format = {
        'setting name': {
            'value': value,
            'mtime': datetime,
        },
    }
    """
    settings = SETTINGS.copy()
    for setting in SETTINGS:
      value, mtime = cls.GetItem(setting)
      settings[setting]['value'] = value
      settings[setting]['mtime'] = mtime
    return settings