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
"""auth module tests."""

import logging

import tests.appenginesdk

import mock
import stubout

from google.appengine.api import users
from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest
from simian import settings
from simian.mac import models
from simian.mac.common import auth


class AuthModuleTest(basetest.TestCase):

  def setUp(self):
    self.stubs = stubout.StubOutForTesting()

    self.email = 'foouser@example.com'

    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL=self.email,
        USER_ID='123',
        USER_IS_ADMIN='0',
        TESTONLY_OAUTH_SKIP_CACHE='1',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()
    settings.ADMINS = ['admin@example.com']

  def tearDown(self):
    self.stubs.UnsetAll()

  @mock.patch.object(auth.users, 'get_current_user', return_value=None)
  def testDoUserAuthWithNoUser(self, _):
    self.assertRaises(auth.NotAuthenticated, auth.DoUserAuth)

  def testDoUserAuthAnyDomainUserSuccess(self):
    self.stubs.Set(auth.settings, 'ALLOW_ALL_DOMAIN_USERS_READ_ACCESS', True)

    self.assertEqual(self.email, auth.DoUserAuth().email())


  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testDoUserAuthWithIsAdminTrueSuccess(self, _):
    self.assertEqual(self.email, auth.DoUserAuth(is_admin=True).email())

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  def testDoUserAuthWithIsAdminTrueFailure(self, _):
    self.assertRaises(auth.IsAdminMismatch, auth.DoUserAuth, is_admin=True)

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  @mock.patch.object(auth, 'IsSupportUser', return_value=False)
  @mock.patch.object(auth, 'IsSecurityUser', return_value=False)
  @mock.patch.object(auth, 'IsPhysicalSecurityUser', return_value=True)
  def testDoUserAuthWithAllDomainUsersOff(self, *_):
    self.stubs.Set(auth.settings, 'ALLOW_ALL_DOMAIN_USERS_READ_ACCESS', False)

    self.assertEqual(self.email, auth.DoUserAuth().email())

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  @mock.patch.object(auth, 'IsSupportUser', return_value=False)
  @mock.patch.object(auth, 'IsSecurityUser', return_value=False)
  @mock.patch.object(auth, 'IsPhysicalSecurityUser', return_value=False)
  def testDoUserAuthWithAllDomainUsersOffFailure(self, *_):
    self.stubs.Set(auth.settings, 'ALLOW_ALL_DOMAIN_USERS_READ_ACCESS', False)

    self.assertRaises(auth.NotAuthenticated, auth.DoUserAuth)

  def testDoOAuthAuthSuccessSettings(self):
    """Test DoOAuthAuth() with success, where user is in settings file."""
    email = 'zerocool@example.com'
    user_service_stub = self.testbed.get_stub(testbed.USER_SERVICE_NAME)
    user_service_stub.SetOAuthUser(email, scopes=[auth.OAUTH_SCOPE])

    auth.settings.OAUTH_USERS = [email]
    self.assertEqual(email, auth.DoOAuthAuth().email())

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testDoOAuthAuthSuccess(self, _):
    """Test DoOAuthAuth() with success, where user is in KeyValueCache."""

    email = 'hal@example.com'
    user_service_stub = self.testbed.get_stub(testbed.USER_SERVICE_NAME)
    user_service_stub.SetOAuthUser(email, scopes=[auth.OAUTH_SCOPE])
    auth.settings.OAUTH_USERS = []

    auth.models.KeyValueCache.MemcacheWrappedSet(
        'oauth_users', 'text_value', auth.util.Serialize([email]))

    self.assertEqual(email, auth.DoOAuthAuth(is_admin=True).email())

  @mock.patch.object(
      auth.oauth, 'get_current_user', side_effect=auth.oauth.OAuthRequestError)
  def testDoOAuthAuthOAuthNotUsed(self, _):
    """Test DoOAuthAuth() where OAuth was not used at all."""
    self.assertRaises(auth.NotAuthenticated, auth.DoOAuthAuth)

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  def testDoOAuthAuthAdminMismatch(self, _):
    """Test DoOAuthAuth(is_admin=True) where user is not admin."""
    email = 'zerocool@example.com'

    user_service_stub = self.testbed.get_stub(testbed.USER_SERVICE_NAME)
    user_service_stub.SetOAuthUser(email, scopes=[auth.OAUTH_SCOPE])

    self.assertRaises(auth.IsAdminMismatch, auth.DoOAuthAuth, is_admin=True)

  def testDoOAuthAuthWhereNotValidOAuthUser(self):
    """Test DoOAuthAuth() where oauth user is not authorized."""
    email = 'zerocool@example.com'
    auth.settings.OAUTH_USERS = []

    user_service_stub = self.testbed.get_stub(testbed.USER_SERVICE_NAME)
    user_service_stub.SetOAuthUser(email, scopes=[auth.OAUTH_SCOPE])

    self.assertRaises(auth.NotAuthenticated, auth.DoOAuthAuth)

  def testDoAnyAuth(self):
    """Test DoAnyAuth()."""

    email = 'zerocool@example.com'
    require_level = 123

    with mock.patch.object(auth, 'DoUserAuth', return_value=email) as m:
      self.assertEqual(auth.DoAnyAuth(is_admin=True), email)
      m.assert_called_once_with(is_admin=True)

    with mock.patch.object(
        auth, 'DoUserAuth', side_effect=auth.IsAdminMismatch):
      self.assertRaises(auth.IsAdminMismatch, auth.DoAnyAuth, is_admin=True)

    with mock.patch.object(
        auth, 'DoUserAuth', side_effect=auth.NotAuthenticated):
      with mock.patch.object(
          auth.gaeserver, 'DoMunkiAuth', return_value='user') as m:
        self.assertEqual(auth.DoAnyAuth(
            is_admin=True, require_level=require_level), 'user')
        m.assert_called_once_with(require_level=require_level)

    with mock.patch.object(
        auth, 'DoUserAuth', side_effect=auth.NotAuthenticated):
      with mock.patch.object(
          auth.gaeserver, 'DoMunkiAuth',
          side_effect=auth.gaeserver.NotAuthenticated):
        self.assertRaises(
            auth.base.NotAuthenticated,
            auth.DoAnyAuth, is_admin=True, require_level=require_level)

  @mock.patch.object(
      auth, '_GetGroupMembers', return_value=['admin4@example.com'])
  def testIsAdminUserTrue(self, _):
    """Test IsAdminUser() with a passed email address that is an admin."""
    admin_email = 'admin4@example.com'
    self.assertTrue(auth.IsAdminUser(admin_email))

  @mock.patch.object(auth, '_GetGroupMembers', return_value=['foo@example.com'])
  def testIsAdminUserFalse(self, _):
    """Test IsAdminUser() with a passed email address that is not an admin."""
    self.assertFalse(auth.IsAdminUser('admin4@example.com'))

  @mock.patch.object(
      auth, '_GetGroupMembers', return_value=['admin5@example.com'])
  def testIsAdminUserWithNoPassedEmail(self, _):
    """Test IsAdminUser() with no passed email address."""
    self.assertFalse(auth.IsAdminUser())

  @mock.patch.object(auth, '_GetGroupMembers', return_value=[])
  def testIsAdminUserBootstrap(self, _):
    """Test IsAdminUser() where no admins are defined."""
    admin_email = 'admin4@example.com'
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL=admin_email,
        USER_IS_ADMIN='1')

    self.assertTrue(auth.IsAdminUser(admin_email))

  @mock.patch.object(auth, '_GetGroupMembers', return_value=[])
  def testIsAdminUserBootstrapFalse(self, _):
    """Test IsAdminUser() where no admins are defined, but user not admin."""
    self.assertFalse(auth.IsAdminUser(self.email))

  def testIsGroupMemberWhenSettings(self):
    """Test IsGroupMember()."""
    group_members = ['support1@example.com', 'support2@example.com']
    group_name = 'foo_group'
    setattr(auth.settings, group_name.upper(), group_members)

    models.KeyValueCache.MemcacheWrappedSet(group_name, 'text_value', '[]')

    self.assertTrue(auth.IsGroupMember(group_members[0], group_name=group_name))

  def testIsGroupMemberWhenSettingsWithNoPassedEmail(self):
    """Test IsGroupMember()."""
    group_members = [self.email, 'support2@example.com']

    group_name = 'foo_group_two'
    setattr(auth.settings, group_name.upper(), group_members)

    models.KeyValueCache.MemcacheWrappedSet(group_name, 'text_value', '[]')

    self.assertTrue(auth.IsGroupMember(group_name=group_name))

  def testIsGroupMemberWhenLiveConfigAdminUser(self):
    """Test IsGroupMember()."""
    email = 'support4@example.com'
    group_members = ['support1@example.com', 'support2@example.com']
    group_name = 'foo_group'

    auth.models.KeyValueCache.MemcacheWrappedSet(
        group_name, 'text_value', auth.util.Serialize([email]))

    self.assertTrue(auth.IsGroupMember(email, group_name=group_name))

  def testIsGroupMemberWhenNotAdmin(self):
    """Test IsGroupMember()."""
    email = 'support5@example.com'
    group_members = ['support1@example.com', 'support2@example.com']
    group_name = 'support_users'

    auth.models.KeyValueCache.MemcacheWrappedSet(
        group_name, 'text_value', auth.util.Serialize(group_members))

    self.assertFalse(auth.IsGroupMember(email, group_name=group_name))


  @mock.patch.object(auth, 'DoUserAuth', return_value=True)
  @mock.patch.object(auth.PermissionResolver, '_IsAllowedToPropose')
  def testIsAllowedTo(self, mock_is_allowed_to_propose, _):
    """Test PermissionResolver.IsAllowedTo."""
    test_resolver = auth.PermissionResolver('task')

    auth.PermissionResolver._IsAllowedToPropose().AndReturn(True)
    auth.PermissionResolver._IsAllowedToPropose().AndReturn(False)

    test_resolver.email = 'user1@example.com'
    test_resolver.task = 'Propose'
    mock_is_allowed_to_propose.return_value = True
    self.assertTrue(test_resolver.IsAllowedTo())

    mock_is_allowed_to_propose.return_value = False
    self.assertFalse(test_resolver.IsAllowedTo())

  @mock.patch.object(auth, 'DoUserAuth', side_effect=auth.NotAuthenticated)
  def testIsAllowedToWithoutUser(self, _):
    test_resolver = auth.PermissionResolver('task')
    test_resolver.email = 'user1@example.com'
    test_resolver.task = 'Propose'
    self.assertFalse(test_resolver.IsAllowedTo())

  @mock.patch.object(auth, 'DoUserAuth', return_value=True)
  def testIsAllowedToUnknownTask(self, _):
    test_resolver = auth.PermissionResolver('task')
    test_resolver.email = 'user1@example.com'
    test_resolver.task = 'FakeTask'

    self.assertFalse(test_resolver.IsAllowedTo())

  def testIsAllowedToPropose(self):
    """Test PermissionResolver._IsAllowedToPropose()."""
    test_resolver = auth.PermissionResolver('task')
    email_one = 'user1@example.com'
    email_two = 'user2@example.com'
    email_three = 'user3@example.com'

    with mock.patch.object(auth, 'IsAdminUser', return_value=True):
      test_resolver.email = email_one
      self.assertTrue(test_resolver._IsAllowedToPropose())

    with mock.patch.object(auth, 'IsAdminUser', return_value=False):
      with mock.patch.object(
          auth, 'IsGroupMember', return_value=True) as mock_is_group_member:
        test_resolver.email = email_two
        self.assertTrue(test_resolver._IsAllowedToPropose())
        mock_is_group_member.assert_called_once_with(
            email_two, 'proposals_group', remote_group_lookup=True)

    with mock.patch.object(auth, 'IsAdminUser', return_value=False):
      with mock.patch.object(
          auth, 'IsGroupMember', return_value=False) as mock_is_group_member:
        test_resolver.email = email_three
        self.assertFalse(test_resolver._IsAllowedToPropose())
        mock_is_group_member.assert_called_once_with(
            email_three, 'proposals_group', remote_group_lookup=True)

  def testIsAllowedToUploadProposalsOff(self):
    """Test PermissionResolver._IsAllowedToUpload() with proposals."""
    test_resolver = auth.PermissionResolver('task')
    email_one = 'user1@example.com'
    email_two = 'user2@example.com'

    setattr(auth.settings, 'ENABLE_PROPOSALS_GROUP', False)
    setattr(auth.settings, 'PROPOSALS_GROUP', '')

    with mock.patch.object(auth, 'IsAdminUser', return_value=True):
      test_resolver.email = email_one
      self.assertTrue(test_resolver._IsAllowedToUpload())

    with mock.patch.object(auth, 'IsAdminUser', return_value=False):
      test_resolver.email = email_two
      self.assertFalse(test_resolver._IsAllowedToUpload())

  @mock.patch.object(auth.PermissionResolver, '_IsAllowedToPropose')
  def testIsAllowedToUploadProposalsOn(self, mock_is_allowed_to_propose):
    """Test PermissionResolver._IsAllowedToUpload() without proposals."""
    test_resolver = auth.PermissionResolver('task')
    email_one = 'user1@example.com'
    email_two = 'user2@example.com'

    setattr(auth.settings, 'ENABLE_PROPOSALS_GROUP', True)
    setattr(auth.settings, 'PROPOSALS_GROUP', 'group')

    test_resolver.email = email_one
    mock_is_allowed_to_propose.return_value = True
    self.assertTrue(test_resolver._IsAllowedToUpload())

    test_resolver.email = email_two
    mock_is_allowed_to_propose.return_value = False
    self.assertFalse(test_resolver._IsAllowedToUpload())

  @mock.patch.object(auth, 'IsSupportUser')
  @mock.patch.object(auth.PermissionResolver, '_IsAllowedToPropose')
  def testIsAllowedToViewPacakgesProposalsOn(
      self, mock_is_allowed_to_propose, mock_is_support_user):
    """Test PermissionResolver._IsAllowedToViewPackages() with proposals."""
    test_resolver = auth.PermissionResolver('task')
    email_one = 'user1@example.com'
    email_two = 'user2@example.com'
    email_three = 'user3@example.com'

    setattr(auth.settings, 'ENABLE_PROPOSALS_GROUP', True)
    setattr(auth.settings, 'PROPOSALS_GROUP', 'group')

    test_resolver.email = email_one
    mock_is_allowed_to_propose.return_value = True
    self.assertTrue(test_resolver._IsAllowedToViewPackages())

    test_resolver.email = email_two
    mock_is_support_user.return_value = True
    mock_is_allowed_to_propose.return_value = False
    self.assertTrue(test_resolver._IsAllowedToViewPackages())

    test_resolver.email = email_three
    mock_is_support_user.return_value = False
    self.assertFalse(test_resolver._IsAllowedToViewPackages())

  @mock.patch.object(auth, 'IsSupportUser')
  @mock.patch.object(auth, 'IsAdminUser')
  def testIsAllowedToViewPacakgesProposalsOff(
      self, mock_is_admin_user, mock_is_support_user):
    """Test PermissionResolver._IsAllowedToViewPackages() without proposals."""
    test_resolver = auth.PermissionResolver('task')
    email_one = 'user1@example.com'
    email_two = 'user2@example.com'
    email_three = 'user3@example.com'

    setattr(auth.settings, 'ENABLE_PROPOSALS_GROUP', False)
    setattr(auth.settings, 'PROPOSALS_GROUP', '')

    test_resolver.email = email_one
    mock_is_admin_user.return_value = True
    self.assertTrue(test_resolver._IsAllowedToViewPackages())

    test_resolver.email = email_two
    mock_is_admin_user.return_value = False
    mock_is_support_user.return_value = True
    self.assertTrue(test_resolver._IsAllowedToViewPackages())

    test_resolver.email = email_three
    mock_is_support_user.return_value = False
    self.assertFalse(test_resolver._IsAllowedToViewPackages())

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, '_GetGroupMembers', return_value=[])
  @mock.patch.dict(settings.__dict__, {
      'ALLOW_SELF_REPORT': True, 'AUTH_DOMAIN': 'example.com'})
  @mock.patch.object(auth.users, 'get_current_user')
  def testDoUserAuthWithSelfReportFallbackAccessDenied(
      self, get_current_user, *_):
    get_current_user.return_value = None
    self.assertRaises(
        auth.NotAuthenticated, auth.DoUserAuthWithSelfReportFallback)

    get_current_user.return_value = users.User(email='user1@example.com')
    self.assertRaises(
        auth.NotAuthenticated,
        auth.DoUserAuthWithSelfReportFallback, constrain_username='user2')

    settings.__dict__['ALLOW_SELF_REPORT'] = False
    get_current_user.return_value = users.User(email='user1@example.com')
    self.assertRaises(
        auth.NotAuthenticated, auth.DoUserAuthWithSelfReportFallback)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, '_GetGroupMembers', return_value=[])
  @mock.patch.dict(auth.settings.__dict__, {
      'ALLOW_SELF_REPORT': True, 'AUTH_DOMAIN': 'example.com'})
  @mock.patch.object(auth.users, 'get_current_user')
  def testDoUserAuthWithSelfReportFallbackSucceed(self, get_current_user, *_):
    get_current_user.return_value = users.User(email='user1@example.com')
    self.assertEqual(
        'user1',
        auth.DoUserAuthWithSelfReportFallback(constrain_username='user1'))


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
