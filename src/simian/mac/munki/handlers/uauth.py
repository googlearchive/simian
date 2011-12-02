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

"""Module to handle real user logins via GAE SSO"""



import logging
from google.appengine.ext import webapp
from google.appengine.api import users
from simian import settings
from simian.auth import base
from simian.auth import gaeserver
from simian.auth import settings as auth_settings
from simian.mac.munki import handlers
from simian.mac.common import auth

class Error(Exception):
  """Base error."""


class NotAuthenticated(Error, base.NotAuthenticated):
  """Not Authenticated Error."""


class UserAuth(handlers.AuthenticationHandler, webapp.RequestHandler):
  """Handle for user auth which provides Auth1 token."""

  def get(self):
    """Handle GET."""

    try:
      # already munki authenticated?  return, nothing to do.
      gaeserver.DoMunkiAuth()
      #logging.info('Uauth: session is already authenticated')
      return
    except gaeserver.NotAuthenticated:
      pass

    user = users.get_current_user()
    if not user:
      #logging.error('Uauth: user is not logged in')
      raise NotAuthenticated

    email = user.email()
    if auth.IsAdminUser(email):
      a = gaeserver.AuthSimianServer()
      output = a.SessionCreateUserAuthToken(email, level=gaeserver.LEVEL_ADMIN)
    elif auth.IsSupportUser(email):
      a = gaeserver.AuthSimianServer()
      output = a.SessionCreateUserAuthToken(email, level=gaeserver.LEVEL_BASE)
    else:
      logging.error('Uauth: user %s is not an admin', email)
      raise NotAuthenticated

    if output:
      #logging.info('Uauth: success, token = %s', output)
      self.response.headers['Set-Cookie'] = '%s=%s; secure; httponly;' % (
          auth_settings.AUTH_TOKEN_COOKIE, output)
      self.response.out.write(auth_settings.AUTH_TOKEN_COOKIE)
    else:
      #logging.info('Uauth: unknown token')
      raise NotAuthenticated

  def post(self):
    """Handle POST.

    Because the appengine_rpc module, used by simian.client.UAuth class, uses
    the POST http method, define this handler which mirrors the functionaly
    of the GET method.
    """
    return self.get()