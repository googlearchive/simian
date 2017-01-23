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
"""auth module."""

import logging

from google.appengine.api import memcache
from google.appengine.api import oauth
from google.appengine.api import users
from google.appengine.ext import db


from simian import settings
from simian.auth import base
from simian.auth import gaeserver
from simian.mac import models
from simian.mac.common import util


ACL_GROUPS = {
    'admins': 'Admins',
    'support_users': 'Support Users',
    'security_users': 'Security Users',
    'physical_security_users': 'Physical Security Users',
}

# Permissions that can be verified by PermissionReslover()
PROPOSE = 'Propose'
UPLOAD = 'Upload'
VIEW_PACKAGES = 'ViewPackages'
OAUTH_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'


class Error(Exception):
  """Base."""


class NotAuthenticated(base.NotAuthenticated, Error):
  """Not authenticated."""


class IsAdminMismatch(NotAuthenticated):
  """Test for IsAdmin mismatch."""


class PermissionResolver(object):
  """Resolves user permissions using rules defined as helper functions."""

  def __init__(self, task, email=None):
    """Initializes object to resolve permissions for a given user."""
    self.task = task
    self.email = email

  def IsAllowedTo(self):
    """Returns true if user is allowed to complete task."""
    try:
      user = DoUserAuth()
    except NotAuthenticated:
      return False
    if not self.email:
      self.email = user.email()
    try:
      rule = getattr(self, '_IsAllowedTo%s' % self.task)
    except AttributeError:
      print 'error'
      return False
    return rule()

  def _IsAllowedToPropose(self):
    """Returns true if email is allowed to propose packages."""
    return _IsAllowedToPropose(self.email)

  def _IsAllowedToUpload(self):
    """Returns true if email is allowed to upload packages."""
    return _IsAllowedToPropose(self.email)

  def _IsAllowedToViewPackages(self):
    """Returns true if email is allowed to view package details."""
    return _IsAllowedToPropose(self.email) or IsSupportUser(self.email)


def HasPermission(task, email=None):
  resolver = PermissionResolver(task, email)
  return resolver.IsAllowedTo()


def _GetGroupMembers(group_name):
  """Returns a set of email addresses that are members of a given group.

  Args:
    group_name: str group name to return the members of.
  Returns:
    List of email addresses of members, or an empty list for unknown groups.
  """
  members = getattr(settings, group_name.upper(), [])
  try:
    json_members = models.KeyValueCache.MemcacheWrappedGet(
        group_name, 'text_value')
    if json_members:
      members.extend(util.Deserialize(json_members))
  except (db.Error, util.DeserializeError):
    pass
  return members


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
    raise NotAuthenticated('DoUserAuthFalsy')
  email = user.email()

  if is_admin and not IsAdminUser(email):
    raise IsAdminMismatch

  if settings.ALLOW_ALL_DOMAIN_USERS_READ_ACCESS:
    return user

  if IsAdminUser(email):
    return user
  elif IsSupportUser(email):
    return user
  elif IsSecurityUser(email):
    return user
  elif IsPhysicalSecurityUser(email):
    return user
  elif _IsAllowedToPropose(email):
    return user
  else:
    raise NotAuthenticated('DoUserAuthUnknownUser')


def DoUserAuthWithSelfReportFallback(constrain_username=None):
  """Verify user auth has occured or try fallback to Self Report.

  Args:
    constrain_username: String. Constrain username.
  Returns:
    String, Username in case of fallback, None otherwise.
  Raises:
    NotAuthenticated: there is no authenticated user for this request.
  """
  try:
    DoUserAuth()
  except NotAuthenticated:
    if not settings.ALLOW_SELF_REPORT:
      raise
    user = users.get_current_user()
    if not user:
      raise
    email = user.email()
    if not email.endswith('@' + settings.AUTH_DOMAIN):
      raise
    username = email[:-len(settings.AUTH_DOMAIN) - 1]
    if constrain_username and constrain_username != username:
      raise
    return username
  return None


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
    user = oauth.get_current_user(OAUTH_SCOPE)
  except oauth.OAuthRequestError:
    raise NotAuthenticated('OAuthRequestError')

  try:
    if oauth.get_client_id(OAUTH_SCOPE) != settings.OAUTH_CLIENT_ID:
      raise NotAuthenticated('mismatched OAUTH_CLIENT_ID')
  except AttributeError:
    raise NotAuthenticated('OAUTH_CLIENT_ID not set')

  email = user.email()

  if is_admin is not None and not IsAdminUser(email):
    raise IsAdminMismatch

  if email in _GetGroupMembers('oauth_users'):
    return user

  logging.warning('OAuth user unknown: %s', email)
  raise NotAuthenticated('DoOAuthAuthUnknownUser')


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
    gaeserver.NotAuthenticated: there is no authentication user for this
        request.
  """
  # TODO(user): The unexpected return of two different return classes
  # here can be hard to code around.  We should fix this someday if we
  # start using the return value more frequently, rather than just
  # calling this as a procedure to cause auth to occur.
  try:
    return DoUserAuth(is_admin=is_admin)
  except IsAdminMismatch:
    raise
  except NotAuthenticated:
    pass

  # gaeserver.NotAuthenticated will be raised in the case of failure.
  return gaeserver.DoMunkiAuth(require_level=require_level)


def IsGroupMember(email=None, group_name=None, remote_group_lookup=False):
  """Returns True if email is a member of the group.

  Args:
    email: str, optional, default current user, fully qualified email address
        e.g. "user@example.com".
    group_name: str, group name to check for membership of.
    remote_group_lookup: str, optional, default False, True to use lookup group
        membership in remote group system.
  Returns:
    True if user is part of the group_name, False if not.
  """
  if not email:
    email = users.get_current_user().email()


  if email in _GetGroupMembers(group_name):
    return True

  return False


def _IsAllowedToPropose(email):
  if IsAdminUser(email):
    return True

  if settings.ENABLE_PROPOSALS_GROUP and settings.PROPOSALS_GROUP:
    if IsGroupMember(email, 'proposals_group', remote_group_lookup=True):
      return True

  return False


def IsAdminUser(email=None):
  """Returns True if email is a Simian admin.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
        then current authenticated user is used.
  Returns:
    True if user is admin, False if not
  """
  if not email:
    email = users.get_current_user().email()

  admin_users = _GetGroupMembers('admins')
  if email in admin_users:
    return True

  # If there are no defined admins in settings or KeyValueCache, provide GAE
  # Developers/etc. admin access for bootstrapping purposes.
  if not admin_users:
    logging.warning(
        'No admins defined! Configure admins in Admin Tools -> ACL Groups.')
    return users.is_current_user_admin()

  return False


def IsSupportUser(email=None):
  """Returns True if email is part of the support group.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
           then current authenticated user is used.
  Returns:
    True if user is part of the support group, False if not.
  """
  return IsGroupMember(
      email=email, group_name='support_users', remote_group_lookup=True)


def IsSecurityUser(email=None):
  """Returns True if email is part of the security group.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
           then current authenticated user is used.
  Returns:
    True if user is part of the security group, False if not.
  """
  return IsGroupMember(
      email=email, group_name='security_users', remote_group_lookup=True)


def IsPhysicalSecurityUser(email=None):
  """Returns True if email is part of the physical security group.

  Args:
    email: str, fully qualified, e.g. "user@example.com". If not provided then
           then current authenticated user is used.
  Returns:
    True if user is part of the physical security group, False if not.
  """
  return IsGroupMember(
      email=email, group_name='physical_security_users',
      remote_group_lookup=True)


