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
"""Simian Settings Models."""

from simian.mac.models import base

SETTINGS = {
    'api_info_key': {
        'type': 'random_str',
        'title': 'API Info Key',
        'comment': 'Consider updating API clients before changing value.',
    },
    'apple_auto_promote_enabled': {
        'type': 'bool',
        'title': 'Apple Update Auto-Promotion Enabled',
        'comment': 'Items auto-promote through release tracks.',
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
        'comment': ('New updates not requiring a restart are set as unattended'
                    ' automatically.'),
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
    'approval_required': {
        'type': 'bool',
    },
    'client_site_enabled': {
        'type': 'bool',
        'title': 'Display Client Site/Office',
        'comment': 'If enabled, data is displayed in Summary and Host reports.',
        'default': False,
    },
    'icons_gcs_bucket': {
        'type': 'string',
        'title': 'Dedicated Cloud Storage Bucket for icons',
    },
    'list_of_categories': {
        'type': 'string',
        'title': 'Categories',
        'comment': 'Software categories as a comma-seperated list.',
        'default': 'Productivity, Developer Tools, Utilities',
    },
    'email_admin_list': {
        'type': 'string',
        'title': 'Admin List Email',
        'comment': 'Server notifications are emailed to this address',
        'default': '',
    },
    'email_domain': {
        'type': 'string',
        'title': 'Email Domain',
    },
    'email_sender': {
        'type': 'string',
        'title': 'Email Sender',
        'comment': 'e.g. Simian Team <admin@example.com>',
        'default': '',
    },
    'email_reply_to': {
        'type': 'string',
        'title': 'Email reply-to',
        'comment': 'e.g. Simian Team <admin@example.com>',
        'default': '',
    },
    'email_on_every_change': {
        'type': 'bool',
        'title': 'Notify Admins of all changes.',
        'comment': 'Check to send a mail to all admins on every change.',
        'default': False,
    },
    'hour_start': {
        'type': 'integer',
        'title': 'UTC hour to start allowing Apple SUS Auto-Promote.',
        'comment': 'Restricts Apple SUS promotion to business hours only.',
        'default': 14,
    },
    'hour_stop': {
        'type': 'integer',
        'title': 'UTC hour to stop allowing Apple SUS Auto-Promote.',
        'comment': 'Restricts Apple SUS promotion to business hours only.',
        'default': 20,
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
    },
    'release_report_salutation': {
        'type': 'string',
        'title': 'Release Report Salutation',
        'comment': 'e.g. "Dear Users,"',
        'default': 'Dear Users,'
    },
    'release_report_title': {
        'type': 'string',
        'title': 'Release Report Title',
        'comment': 'e.g. "Software Release Report"',
        'default': 'Software Release Report',
    },
    'release_report_subject_flag': {
        'type': 'string',
        'title': 'Release Report Subject Flag',
        'comment': ('used when one or more update has a force by date, e.g. '
                    '"IMPORTANT PLEASE READ"'),
        'default': 'IMPORTANT PLEASE READ',
    },
    'release_report_introduction': {
        'type': 'string',
        'title': 'Release Report Introduction',
        'comment': ('e.g. "The following packages have been added to '
                    'Managed Software Update."'),
        'default': ('The following packages have been added to '
                    'Managed Software Update.'),
    },
    'release_report_introduction_warning': {
        'type': 'string',
        'title': 'Release Report Introduction Warning',
        'comment': 'e.g. "Some of these packages have installation deadlines."',
        'default': 'Some of these packages have installation deadlines.',
    },
    'release_report_managed_install_text': {
        'type': 'string',
        'title': 'Release Report Managed Install Text',
        'comment': 'e.g. "will install on all"',
        'default': 'will install on all',
    },
    'release_report_managed_update_and_optional_text': {
        'type': 'string',
        'title': 'Release Report Managed Update and Optional Install Text',
        'comment': ('e.g. "will be available as an optional install '
                    'and will update earlier versions"'),
        'default': ('will be available as an optional install and will '
                    'update earlier versions'),
    },
    'release_report_managed_update_text': {
        'type': 'string',
        'title': 'Release Report Managed Update Text',
        'comment': 'e.g. "will update earlier versions"',
        'default': 'will update earlier versions',
    },
    'release_report_optional_install_text': {
        'type': 'string',
        'title': 'Release Report Optional Install Text',
        'comment': 'e.g. "will be available as an optional install"',
        'default': 'will be available as an optional install',
    },
    'release_report_unattended_and_forced_text': {
        'type': 'string',
        'title': 'Release Report Unattended and Forced Text',
        'comment': ('e.g. "this should install silently in the backgroup but '
                    'if it can not it will be forced at 1PM local time on"'),
        'default': ('this should install silently in the backgroup but if it '
                    'can not it will be forced at 1PM local time on'),
    },
    'release_report_forced_text': {
        'type': 'string',
        'title': 'Release Report Forced Install Text',
        'comment': 'e.g. "this will be forced at 1PM local time on"',
        'default': 'this will be forced at 1PM local time on',
    },
    'release_report_restart_required_text': {
        'type': 'string',
        'title': 'Release Report Restart Required Text',
        'comment': 'e.g. "a restart is required for this pacakge"',
        'default': 'a restart is required for this pacakge',
    },
    'release_report_signature': {
        'type': 'string',
        'title': 'Release Report Signature',
        'comment': 'e.g. "Sincerely,"',
        'default': 'Sincerely,',
    },
    'release_report_version_verb': {
        'type': 'string',
        'title': 'Release Report Version Verb',
        'comment': 'comes before the version name, e.g. "running".',
        'default': 'running',
    },
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

    Returns:
      Dictionary of all settings, in the following format:
        {
          'setting name': {
              'value': value,
              'mtime': datetime,
          },
        }
    """
    settings = {}
    for setting in SETTINGS:
      value, mtime = cls.GetItem(setting)
      settings[setting] = {
          'value': value,
          'mtime': mtime,
      }
    for k in cls.all(keys_only=True):
      setting = k.name()
      value, mtime = cls.GetItem(setting)
      settings[setting] = {
          'value': value,
          'mtime': mtime,
      }

    return settings

  @classmethod
  def GetSettingsWithDescription(cls):
    """Return a dictionary of settings presented in SETTINGS."""
    settings = SETTINGS.copy()
    for setting in SETTINGS:
      value, mtime = cls.GetItem(setting)
      settings[setting]['value'] = value
      settings[setting]['mtime'] = mtime

    return settings
