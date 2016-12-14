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
#
#

"""Utility module including code to obtain settings.

Classes:
  CaIdParameters: class container for CA parameters

Functions:
  GetCaId: function to return CA parameters obtained from settings
"""



import logging
import re

# ca_id sanity check
CA_ID_RE = re.compile(r'^[A-Z][0-9A-Z]+$')
# Constants for manipulating server/CA identity in structures.
L_CA_PUBLIC_CERT_PEM = 'CA_PUBLIC_CERT_PEM'
L_SERVER_PUBLIC_CERT_PEM = 'SERVER_PUBLIC_CERT_PEM'
L_SERVER_PRIVATE_KEY_PEM = 'SERVER_PRIVATE_KEY_PEM'
L_REQUIRED_ISSUER = 'REQUIRED_ISSUER'


class Error(Exception):
  """Base error."""


class CaParametersError(Error):
  """Loading/finding (ca, server certs, keys) error."""


class CaParameters(object):
  """Container for CA parameters."""
  ca_public_cert_pem = None
  server_public_cert_pem = None
  server_private_key_pem = None
  required_issuer = None
  ca_id = None

  def __repr__(self):
    values = []
    for k in dir(self):
      if not k.startswith('_'):
        values.append('%s=%s' % (k, getattr(self, k)))
    return '<%s>' % ' '.join(values)


def GetCaId(settings):
  """Get ca_id to be used with GetCaParameters().

  Args:
    settings: object with attribute level access to settings parameters.
  Returns:
    str like "FOO" or None (use primary parameters)
  """
  return getattr(settings, 'CA_ID', None)


def GetCaParameters(settings, ca_id=0, omit_server_private_key=False):
  """Get ca/cert parameters for CA named ca_id.

  Note, subtle: If no ca_id value is supplied, the default value from
  settings.CA_ID is used for the ca_id.  This value might make the chosen
  parameters be NOT from the defaults (no prefix on the settings names).
  However, if None value is supplied for ca_id then the CA_ID of default
  (no specific CA_ID specified) is used. See the table below for examples.

  ca_id argument       settings     settings
  ------------------   ------------ -------------------------------
  ca_id (unspecified)  CA_ID="FOO"  uses:  FOO_CA_PUBLIC_CERT_PEM
  ca_id (unspecified)  CA_ID=None   uses:  CA_PUBLIC_CERT_PEM
  ca_id=None           CA_ID=None   uses:  CA_PUBLIC_CERT_PEM
  ca_id=None           CA_ID="FOO"  uses:  CA_PUBLIC_CERT_PEM
  ca_id="BAR"          CA_ID=None   uses:  BAR_CA_PUBLIC_CERT_PEM
  ca_id="BAR"          CA_ID="FOO"  uses:  BAR_CA_PUBLIC_CERT_PEM

  Args:
    settings: object with attribute level access to settings parameters.
    ca_id: str or None (default), identifies the CA/server cert/keys.
    omit_server_private_key: bool, True to omit the server's private key, for
        use when calling from clients.  Default False, which includes the key.
  Returns:
    CaParameters instance.
  Raises:
    CaIdError: if any errors occur loading keys/certs for ca_id
  """
  if ca_id is 0:
    ca_id = GetCaId(settings)

  if ca_id is not None and not CA_ID_RE.match(ca_id):
    raise CaParametersError('invalid ca_id')

  settings_params = [
      L_CA_PUBLIC_CERT_PEM,
      L_SERVER_PUBLIC_CERT_PEM,
      L_REQUIRED_ISSUER,
  ]

  optional_params = []

  if not omit_server_private_key:
    settings_params.append(L_SERVER_PRIVATE_KEY_PEM)
    optional_params.append(L_SERVER_PRIVATE_KEY_PEM)

  ca_params = CaParameters()

  try:
    for settings_name in settings_params:
      if ca_id:
        settings_k = '%s_%s' % (ca_id, settings_name)
      else:
        settings_k = settings_name
      param_k = settings_name.lower()
      try:
        v = getattr(settings, settings_k)
      except AttributeError:
        if settings_name in optional_params:
          v = None
        else:
          raise
      setattr(ca_params, param_k, v)
  except (AttributeError, ValueError), e:
    logging.error(str(e))
    logging.exception(str(e))
    raise CaParametersError(str(e))

  ca_params.ca_id = ca_id
  return ca_params
