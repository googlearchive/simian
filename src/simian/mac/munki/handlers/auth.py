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

"""Module to handle /pkgs"""



import logging
import os
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from simian.mac.munki import handlers
from simian.mac import models
from simian.auth import base
from simian.auth import settings as auth_settings
from simian.auth import gaeserver
from simian.mac.common import util


class Auth(
    handlers.AuthenticationHandler,
    webapp.RequestHandler):
  """Handler for /auth URL."""

  def GetAuth1Instance(self):
    auth1 = gaeserver.AuthSimianServer()
    try:
      #TODO(user): This needs a testing framework that is setup
      #when running in dev_appserver.
      auth1.LoadSelfKey(gaeserver.GetSimianPrivateKey())
    except gaeserver.ServerCertMissing, e:
      logging.critical('ServerCertMissing details %s' % e)
      raise base.NotAuthenticated
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
    """GET"""
    session = gaeserver.DoMunkiAuth()
    logout = self.request.get('logout')
    if logout:
      gaeserver.LogoutSession(session)

  def post(self):
    """POST"""
    auth1 = self.GetAuth1Instance()

    if self._IsRemoteIpAddressBlocked(os.environ.get('REMOTE_ADDR', '')):
      raise base.NotAuthenticated

    n = self.request.get('n', None)
    m = self.request.get('m', None)
    s = self.request.get('s', None)

    # uncomment for verbose logging on input auth sesssions
    #logging.debug('Input n=%s m=%s s=%s', n, m, s)

    try:
      auth1.Input(n=n, m=m, s=s)
    except ValueError, e:
      logging.exception('invalid parameters to auth1.Input()')
      raise base.NotAuthenticated

    output = auth1.Output()
    auth_state = auth1.AuthState()

    if auth_state == gaeserver.base.AuthState.OK:
      if output:
        self.response.headers['Set-Cookie'] = '%s=%s; secure; httponly;' % (
            auth_settings.AUTH_TOKEN_COOKIE, output)
        self.response.out.write(auth_settings.AUTH_TOKEN_COOKIE)
      else:
        logging.critical('Auth is OK but there is no output.')
        raise base.NotAuthenticated
    elif auth_state == gaeserver.base.AuthState.FAIL:
      raise base.NotAuthenticated
    elif output:
      self.response.out.write(output)
    else:
      logging.critical('auth_state is %s but no output.', auth_state)
      raise base.NotAuthenticated  # technically 500, 403 for security