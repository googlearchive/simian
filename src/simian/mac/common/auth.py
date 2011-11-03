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

"""auth module"""




import logging
from google.appengine.api import users
from google.appengine.api import oauth
from google.appengine.ext import db
from simian import settings
from simian.auth import gaeserver
from simian.auth import base
from simian.mac import models
from simian.mac.common import util


class Error(Exception):
  """Base"""


class NotAuthenticated(base.NotAuthenticated, Error):
  """Not authenticated."""


class IsAdminMismatch(NotAuthenticated):
  """Test for IsAdmin mismatch."""


def DoUserAuth(is_admin=None):
  """Verify user auth has occured.

  Args:
    is_admin: Boolean. When True, checks if the user is an admin.
  Returns:
    users.User() object.
  Raises:
    NotAuthenticated: there is no authenticated user for this request.
    IsAdminMismatch: the current user is not an administrator.
  """
  user = users.get_current_user()
  if not user:
    raise NotAuthenticated
  if is_admin is not None and not IsAdminUser(user.email()):
    raise IsAdminMismatch
  return user


def DoOAuthAuth(is_admin=None, require_level=None):
  """Verify OAuth was used with a valid account.

  Args:
    is_admin: Boolean. When True, checks if the user is an admin.
    require_level: int, default None, when defined,
        requires that a session be at level x.
  Returns:
    users.User() object.
  Raises:
    NotAuthenticated: there is no authenticated user for this request.
    IsAdminMismatch: the current user is not an administrator.
  """
  # TODO(user): make use of require_level.
  try:
    user = oauth.get_current_user()
  except oauth.OAuthRequestError, e:
    raise NotAuthenticated

  email = user.email()

  if is_admin is not None and not IsAdminUser(email):
    raise IsAdminMismatch

  if email in settings.OAUTH_USERS:
    return user

  oauth_users = models.KeyValueCache.MemcacheWrappedGet(
      'oauth_users', 'text_value')
  if oauth_users:
    oauth_users = util.Deserialize(oauth_users)
    if email in oauth_users:
      return user

  logging.warning('OAuth user unknown: %s', email)
  raise NotAuthenticated


def DoAnyAuth(is_admin=None, require_level=None):
  """Verify that any form of auth has occured.

  Includes DoUserAuth and gaeserver.DoMunkiAuth.

  Args:
    is_admin: bool, default False, when True,
        requires that the user is an admin.
    require_level: int, default None, when defined,
        requires that a session be at level x.
  Returns:
    users.User() object if DoUserAuth succeeded
    models.AuthSession entity if DoMunkiAuth succeeded
  Raises:
    NotAuthenticated: there is no authentication user for this request.
    IsAdminMismatch: the current user is not an administrator.
  """
  #TODO(user): The unexpected return of two different return classes
  #here can be hard to code around.  We should fix this someday if we
  #start using the return value more frequently, rather than just
  #calling this as a procedure to cause auth to occur.
  try:
    return DoUserAuth(is_admin=is_admin)
  except IsAdminMismatch:
    raise
  except NotAuthenticated:
    pass

  try:
    return gaeserver.DoMunkiAuth(require_level=require_level)
  except gaeserver.NotAuthenticated:
    pass

  raise NotAuthenticated




def IsAdminUser(email=None):
  """Returns True if email is a Simian admin.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
        then current authenticated user is used.
  Returns:
    True if user is admin, False if not
  """
  user = None
  if not email:
    user = users.get_current_user()
    email = user.email()

  if email in settings.ADMINS:
    return True

  if not user:
    user = users.get_current_user()
  if user and user.email() == email and users.is_current_user_admin():
    return True

  try:
    admins = models.KeyValueCache.MemcacheWrappedGet('admins', 'text_value')
    if admins:
      admins = util.Deserialize(admins)
      if email in admins:
        return True
  except (db.Error, util.DeserializeError):
    pass

  return False

def IsSupportStaff(email=None):
  """Returns True if email is part of support staff.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
        then current authenticated user is used.
  Returns:
    True if user is part of support staff, False if not
  """
  if not email:
    email = users.get_current_user().email()

  if email in settings.SUPPORT_STAFF:
    return True

  try:
    support_staff = models.KeyValueCache.MemcacheWrappedGet(
        'support_staff', 'text_value')
    if support_staff:
      support_staff = util.Deserialize(support_staff)
      if email in support_staff:
        return True
  except (db.Error, util.DeserializeError):
    pass

  return False