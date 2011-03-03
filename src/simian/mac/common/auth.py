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




from google.appengine.api import users
from simian.auth import gaeserver
from simian.auth import base


class Error(Exception):
  """Base"""


class NotAuthenticated(base.NotAuthenticated, Error):
  """Not authenticated."""


class IsAdminMismatch(Error):
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
  if is_admin is not None and is_admin != users.is_current_user_admin():
    raise IsAdminMismatch
  return user


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
  except NotAuthenticated:
    pass
  except IsAdminMismatch:
    raise

  try:
    return gaeserver.DoMunkiAuth(require_level=require_level)
  except gaeserver.NotAuthenticated:
    pass

  raise NotAuthenticated

