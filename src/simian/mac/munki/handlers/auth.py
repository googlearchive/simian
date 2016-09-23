#!/usr/bin/env python
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Module to handle /auth"""

import base64
import logging
import os

from simian import auth
from simian import settings
from simian.auth import base
from simian.auth import gaeserver
from simian.mac.munki import handlers


def CreateAuthTokenCookieStr(token):
  return '%s=%s; secure; httponly;' % (auth.AUTH_TOKEN_COOKIE, token)


class Auth(handlers.AuthenticationHandler):
  """Handler for /auth URL."""

  def GetAuth1Instance(self, ca_id=None):
    """Generate an instance of auth1 class and return it.

    Args:
      ca_id: str, default None, the ca_id to pass to LoadCaParameters.
          This value changes the set of server/ca public/priv etc config
          parameters that is used for the Auth1 communication.
    """
    try:
      auth1 = gaeserver.AuthSimianServer()
      auth1.LoadCaParameters(settings, ca_id)
    except gaeserver.CaParametersError, e:
      logging.critical('(ca_id = %s) %s' % (ca_id, str(e)))
      raise base.NotAuthenticated('CaParametersError')
    return auth1

  def _IsRemoteIpAddressBlocked(self, ip):
    """Check if the remote's IP address is within a blocked range.

    Args:
      ip: str, IP address
    Returns:
      True if it is within blocked range, False if not.
    """
    # NOTE(user): for future expansion, one could do something like the
    # following:
    #
    # return models.KeyValueCache.IpInList('auth_bad_ip_blocks', ip)
    #
    # For now we don't need this, so just return False (not blocked).
    return False


  def get(self):
    """GET."""
    logout = self.request.get('logout')

    session = gaeserver.DoMunkiAuth()
    if logout:
      gaeserver.LogoutSession(session)

  def post(self):
    """POST"""
    ca_id = self.request.get('ca_id', None)
    auth1 = self.GetAuth1Instance(ca_id=ca_id)

    if self._IsRemoteIpAddressBlocked(os.environ.get('REMOTE_ADDR', '')):
      raise base.NotAuthenticated('RemoteIpAddressBlocked')

    n = self.request.get('n', None)
    m = self.request.get('m', None)
    s = self.request.get('s', None)

    # uncomment for verbose logging on input auth sesssions
    #logging.debug('Input n=%s m=%s s=%s', n, m, s)

    try:
      auth1.Input(n=n, m=m, s=s)
    except ValueError, e:
      logging.exception('invalid parameters to auth1.Input()')
      raise base.NotAuthenticated('InvalidAuth1InputParams')

    output = auth1.Output()
    auth_state = auth1.AuthState()

    if auth_state == gaeserver.base.AuthState.OK:
      if output:
        self.response.headers['Set-Cookie'] = CreateAuthTokenCookieStr(output)
        self.response.out.write(auth.AUTH_TOKEN_COOKIE)
      else:
        logging.critical('Auth is OK but there is no output.')
        raise base.NotAuthenticated('AuthOkOutputEmpty')
    elif auth_state == gaeserver.base.AuthState.FAIL:
      raise base.NotAuthenticated('AuthStateFail')
    elif output:
      self.response.out.write(output)
    else:
      logging.critical('auth_state is %s but no output.', auth_state)
      # technically 500, 403 for security
      raise base.NotAuthenticated('AuthStateUnknownOutputEmpty')
