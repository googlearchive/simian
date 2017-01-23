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
"""Configuration settings admin handler."""

import httplib
import json
import os

from google.appengine.api import users

from simian.auth import x509

from simian import settings as settings_module
from simian.mac import admin
from simian.mac import models
from simian.mac.admin import xsrf
from simian.mac.common import mail

MISSING = 'Missing'
VALID = 'Valid'
VALIDATION = 'validation'
PEM = {
    'server_private_key_pem': {'type': 'rsapriv'},
    'server_public_cert_pem': {'type': 'x509'},
    'ca_public_cert_pem': {'type': 'x509'},
}


class Config(admin.AdminHandler):
  """Handler for admin/config."""

  def __init__(self, *args, **kwargs):
    super(Config, self).__init__(*args, **kwargs)
    self._post_pem_upload = {
        'ca_public_cert_pem': self._SetRequiredIssuer,
    }

  def _SetRequiredIssuer(self, pem_file):
    """Set settings.REQUIRED_ISSUER to the issuer in this PEM cert.

    Args:
      pem_file: str, pem formatted certificate
    """
    try:
      cert = x509.LoadCertificateFromPEM(pem_file)
      if cert.GetMayActAsCA():
        required_issuer = cert.GetIssuer()
        settings_module.REQUIRED_ISSUER = required_issuer
    except x509.Error:
      pass

  def get(self):
    """GET handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return
    settings = models.Settings.GetSettingsWithDescription()
    for name, d in settings.iteritems():
      d['regex'] = settings_module.GetValidationRegex(name)
    pems = self._GetPems()
    d = {
        'report_type': 'config',
        'settings': sorted(settings.iteritems()),
        'pems': pems
    }
    self.Render('config.html', d)

  def post(self):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(httplib.FORBIDDEN)
      return
    xsrf_token = self.request.get('xsrf_token', None)
    if not xsrf.XsrfTokenValidate(xsrf_token, 'config'):
      self.error(httplib.BAD_REQUEST)
      self.response.out.write(json.dumps(
          {'error': 'Invalid XSRF token. Refresh page and try again.'}))
      return
    if self.request.get('action', None) == 'pem_upload':
      self._PemUpload()
    else:
      self._UpdateSettingValue()

  def NotifyAdminsOfChange(self, setting, value):
    """Notify Admins of changes to Settings."""
    subject_line = 'Simian Settings Change by %s' % (users.get_current_user())
    main_body = '%s set to: %s' % (setting, value)
    mail.SendMail(settings_module.EMAIL_ADMIN_LIST, subject_line, main_body)

  def _UpdateSettingValue(self):
    self.response.headers['Content-Type'] = 'application/json'
    setting = self.request.get('setting', None)
    if settings_module.EMAIL_ON_EVERY_CHANGE:
      self.NotifyAdminsOfChange(setting, self.request.get('value', None))
    if setting and setting in models.SETTINGS:
      setting_type = models.SETTINGS[setting]['type']
      if setting_type in ['integer', 'string']:
        value = self.request.get('value', None)
        try:
          if setting_type == 'integer':
            value = int(value)
          setattr(settings_module, setting.upper(), value)
        except (TypeError, ValueError), e:
          self.error(httplib.BAD_REQUEST)
          self.response.out.write(json.dumps({'error': str(e)}))
        else:
          new_value = getattr(settings_module, setting.upper())
          self.response.out.write(json.dumps(
              {'values': [{'name': 'value', 'value': new_value}]}))
      elif setting_type == 'random_str':
        random_str = os.urandom(16).encode('base64')[:20]
        setattr(settings_module, setting.upper(), random_str)
        if setting == 'xsrf_secret':
          self.redirect(
              '/admin/config?msg=XSRF secret successfully regenerated.')
        else:
          self.response.out.write(json.dumps(
              {'values': [{'name': 'value', 'value': random_str}]}))
      elif setting_type == 'bool':
        value = self.request.get('value', None)
        if value == 'true':
          setattr(settings_module, setting.upper(), True)
        else:
          setattr(settings_module, setting.upper(), False)
        self.response.out.write(json.dumps(
            {'values': [{'name': 'value', 'value': value == 'true'}]}))
    else:
      self.error(httplib.BAD_REQUEST)
      self.response.out.write(json.dumps(
          {'error': 'Trying to set invalid setting.'}))

  def _GetPems(self, pem_settings=None):
    """Returns a dictionary of PEM validation."""
    if not pem_settings:
      pem_settings = {}

    pems = PEM.copy()
    pem_keys = PEM.keys()
    pem_keys.sort()  # orders ca_* to be seen first
    ca_cert = None

    for name in pem_keys:
      if name in pem_settings:
        pem = pem_settings[name]
      else:
        pem = getattr(settings_module, name.upper(), None)
      pems[name]['pem'] = pem
      if pem:
        # TODO(user): move to settings module validation.
        try:
          if 'key' in name:
            settings_module.CheckValuePemRsaPrivateKey(name, pem)
          elif 'cert' in name:
            settings_module.CheckValuePemX509Cert(name, pem)
            try:
              cert = x509.LoadCertificateFromPEM(pem)
              cert.CheckValidity()
              if name == 'ca_public_cert_pem':
                if not cert.GetMayActAsCA():
                  raise ValueError('CA flag not set')
                ca_cert = cert
              elif name == 'server_public_cert_pem':
                if ca_cert is not None:
                  if not cert.IsSignedBy(ca_cert):
                    raise ValueError('Signature does not match CA cert')
            # TODO(user): verify that server_{public,private} are a pair.
            except x509.Error, e:
              raise ValueError(str(e))
          else:
            raise ValueError('Unknown PEM name')
          pems[name][VALIDATION] = VALID
        except ValueError, e:
          pems[name][VALIDATION] = str(e)
      else:
        pems[name][VALIDATION] = MISSING
    return pems

  def _PemUpload(self):
    pem = self.request.get('pem', None)
    pem_file = self.request.get('pem_file', None)

    if not pem or pem not in PEM:
      self.error(httplib.BAD_REQUEST)
      self.response.out.write('Invalid PEM name.')
      return

    valid_pems = self._GetPems({pem: pem_file})
    if valid_pems[pem][VALIDATION] != VALID:
      errmsg = valid_pems[pem][VALIDATION]
      self.redirect('/admin/config?msg=PEM upload failed: %s' % errmsg)
      return

    valid_pems = self._GetPems()

    if (valid_pems[pem][VALIDATION] == VALID and
        getattr(settings_module, 'pem', None)):
      self.error(httplib.BAD_REQUEST)
      self.response.out.write('PEM already present.')
      return

    if not pem_file:
      self.error(httplib.BAD_REQUEST)
      self.response.out.write('Invalid File.')
      return

    try:
      setattr(settings_module, pem, pem_file)
      if pem == 'ca_public_cert_pem':
        self._SetRequiredIssuer(pem_file)
    except ValueError, e:
      self.redirect('/admin/config?msg=PEM upload failed: %s' % str(e))
    else:
      self.redirect('/admin/config?msg=PEM uploaded.')
