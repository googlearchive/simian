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

"""auth module tests."""



import logging
logging.basicConfig(filename='/dev/null')

import tests.appenginesdk
from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.common import auth


class AuthModuleTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testDoUserAuth(self):
    self.stubs.Set(auth, 'users', self.mox.CreateMock(auth.users))
    self.mox.StubOutWithMock(auth, 'IsAdminUser')

    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'
    auth.users.get_current_user().AndReturn(None)  # 1
    auth.users.get_current_user().AndReturn(mock_user) # 2
    auth.users.get_current_user().AndReturn(mock_user) # 3
    mock_user.email().AndReturn(email)
    auth.IsAdminUser(email).AndReturn(True)
    auth.users.get_current_user().AndReturn(mock_user)  # 4
    mock_user.email().AndReturn(email)
    auth.IsAdminUser(email).AndReturn(False)

    self.mox.ReplayAll()
    # 1
    self.assertRaises(auth.NotAuthenticated, auth.DoUserAuth)
    # 2
    self.assertEqual(mock_user, auth.DoUserAuth())
    # 3
    auth.DoUserAuth(is_admin=True)
    # 4
    self.assertRaises(auth.IsAdminMismatch, auth.DoUserAuth, is_admin=True)
    self.mox.VerifyAll()

  def testDoOAuthAuthSuccessSettings(self):
    """Test DoOAuthAuth() with success, where user is in settings file."""
    self.mox.StubOutWithMock(auth.oauth, 'get_current_user')

    mock_user = self.mox.CreateMockAnything()
    mock_oauth_users = self.mox.CreateMockAnything()
    email = 'foouser@example.com'
    auth.settings.OAUTH_USERS = [email]

    auth.oauth.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)

    self.mox.ReplayAll()
    auth.DoOAuthAuth()
    self.mox.VerifyAll()

  def testDoOAuthAuthSuccess(self):
    """Test DoOAuthAuth() with success, where user is in KeyValueCache."""
    self.mox.StubOutWithMock(auth.oauth, 'get_current_user')
    self.mox.StubOutWithMock(auth, 'IsAdminUser')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')
    self.mox.StubOutWithMock(auth.util, 'Deserialize')

    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'
    auth.settings.OAUTH_USERS = []
    oauth_users = [email]

    auth.oauth.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    auth.IsAdminUser(email).AndReturn(True)
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'oauth_users', 'text_value').AndReturn(oauth_users)
    auth.util.Deserialize(oauth_users).AndReturn(oauth_users)

    self.mox.ReplayAll()
    auth.DoOAuthAuth(is_admin=True)
    self.mox.VerifyAll()

  def testDoOAuthAuthOAuthNotUsed(self):
    """Test DoOAuthAuth() where OAuth was not used at all."""
    self.mox.StubOutWithMock(auth.oauth, 'get_current_user')

    auth.oauth.get_current_user().AndRaise(auth.oauth.OAuthRequestError)

    self.mox.ReplayAll()
    self.assertRaises(auth.NotAuthenticated, auth.DoOAuthAuth)
    self.mox.VerifyAll()

  def testDoOAuthAuthAdminMismatch(self):
    """Test DoOAuthAuth(is_admin=True) where user is not admin."""
    self.mox.StubOutWithMock(auth.oauth, 'get_current_user')
    self.mox.StubOutWithMock(auth, 'IsAdminUser')

    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'

    auth.oauth.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    auth.IsAdminUser(email).AndReturn(False)

    self.mox.ReplayAll()
    self.assertRaises(auth.IsAdminMismatch, auth.DoOAuthAuth, is_admin=True)
    self.mox.VerifyAll()

  def testDoOAuthAuthWhereNotValidOAuthUser(self):
    """Test DoOAuthAuth() where oauth user is not authorized."""
    self.mox.StubOutWithMock(auth.oauth, 'get_current_user')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')

    mock_user = self.mox.CreateMockAnything()
    email = 'foouser@example.com'
    auth.settings.OAUTH_USERS = []

    auth.oauth.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'oauth_users', 'text_value').AndReturn(None)

    self.mox.ReplayAll()
    self.assertRaises(auth.NotAuthenticated, auth.DoOAuthAuth)
    self.mox.VerifyAll()

  def testDoAnyAuth(self):
    """Test DoAnyAuth()."""

    is_admin = True
    require_level = 123

    self.mox.StubOutWithMock(auth, 'DoUserAuth')
    self.mox.StubOutWithMock(auth.gaeserver, 'DoMunkiAuth')

    auth.DoUserAuth(is_admin=is_admin).AndReturn('user')

    auth.DoUserAuth(is_admin=is_admin).AndRaise(auth.IsAdminMismatch)

    auth.DoUserAuth(is_admin=is_admin).AndRaise(auth.NotAuthenticated)
    auth.gaeserver.DoMunkiAuth(require_level=require_level).AndReturn('token')

    auth.DoUserAuth(is_admin=is_admin).AndRaise(auth.NotAuthenticated)
    auth.gaeserver.DoMunkiAuth(require_level=require_level).AndRaise(
        auth.gaeserver.NotAuthenticated)

    self.mox.ReplayAll()

    self.assertEqual(auth.DoAnyAuth(is_admin=is_admin), 'user')

    self.assertRaises(
        auth.IsAdminMismatch,
        auth.DoAnyAuth, is_admin=is_admin)

    self.assertEqual(auth.DoAnyAuth(
        is_admin=is_admin, require_level=require_level), 'token')

    self.assertRaises(
        auth.NotAuthenticated,
        auth.DoAnyAuth, is_admin=is_admin, require_level=require_level)

    self.mox.VerifyAll()


# Unit test for AdminUser
  def testIsAdminUserWhenSettings(self):
    """Test IsAdminUser()."""
    admins_list = ['admin1@example.com', 'admin2@example.com']
    self.stubs.Set(auth.settings, 'ADMINS', admins_list)
    self.mox.ReplayAll()
    self.assertTrue(auth.IsAdminUser(admins_list[0]))
    self.mox.VerifyAll()

  def testIsAdminUserWhenSettingsWithNoPassedEmail(self):
    """Test IsAdminUser()."""
    email = 'foouser@example.com'
    admins_list = [email, 'admin2@example.com']
    mock_user = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(auth, 'users')
    auth.users.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    self.stubs.Set(auth.settings, 'ADMINS', admins_list)
    self.mox.ReplayAll()
    self.assertTrue(auth.IsAdminUser())
    self.mox.VerifyAll()

  def testIsAdminUserWhenAEAdminUser(self):
    """Test IsAdminUser()."""
    admin_user = 'admin3@example.com'
    admins_list = ['admin1@example.com', 'admin2@example.com']

    self.stubs.Set(auth.settings, 'ADMINS', admins_list)
    mock_user = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(auth, 'users')
    auth.users.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(admin_user)
    auth.users.is_current_user_admin().AndReturn(True)

    self.mox.ReplayAll()
    self.assertTrue(auth.IsAdminUser(admin_user))
    self.mox.VerifyAll()

  def testIsAdminUserWhenLiveConfigAdminUser(self):
    """Test IsAdminUser()."""
    admin_user = 'admin4@example.com'
    admins_list = ['admin1@example.com', 'admin2@example.com']

    self.stubs.Set(auth.settings, 'ADMINS', admins_list)
    self.mox.StubOutWithMock(auth, 'users')
    auth.users.get_current_user().AndReturn(None)
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'admins', 'text_value').AndReturn('admins serialized')
    auth.util.Deserialize('admins serialized').AndReturn([admin_user])

    self.mox.ReplayAll()
    self.assertTrue(auth.IsAdminUser(admin_user))
    self.mox.VerifyAll()

  def testIsAdminUserWhenNotAdmin(self):
    """Test IsAdminUser()."""
    admin_user = 'admin5@example.com'
    admins_list = ['admin1@example.com', 'admin2@example.com']

    self.stubs.Set(auth.settings, 'ADMINS', admins_list)
    self.mox.StubOutWithMock(auth, 'users')
    auth.users.get_current_user().AndReturn(None)
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'admins', 'text_value').AndReturn('admins serialized')
    auth.util.Deserialize('admins serialized').AndReturn(admins_list)

    self.mox.ReplayAll()
    self.assertFalse(auth.IsAdminUser(admin_user))
    self.mox.VerifyAll()

# Unit test for SupportStaff
  def testIsSupportStaffWhenSettings(self):
    """Test IsSupportStaff()."""
    support_list = ['support1@example.com', 'support2@example.com']
    self.stubs.Set(auth.settings, 'SUPPORT_STAFF', support_list)
    self.mox.ReplayAll()
    self.assertTrue(auth.IsSupportStaff(support_list[0]))
    self.mox.VerifyAll()

  def testIsSupportStaffWhenSettingsWithNoPassedEmail(self):
    """Test IsSupportStaff()."""
    email = 'foouser@example.com'
    support_list = [email, 'support2@example.com']
    mock_user = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(auth, 'users')
    auth.users.get_current_user().AndReturn(mock_user)
    mock_user.email().AndReturn(email)
    self.stubs.Set(auth.settings, 'SUPPORT_STAFF', support_list)
    self.mox.ReplayAll()
    self.assertTrue(auth.IsSupportStaff())
    self.mox.VerifyAll()

  def testIsSupportStaffWhenLiveConfigAdminUser(self):
    """Test IsSupportStaff()."""
    support_user = 'support4@example.com'
    support_list = ['support1@example.com', 'support2@example.com']

    self.mox.StubOutWithMock(auth, 'users')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'support_staff', 'text_value').AndReturn('support staff serialized')
    auth.util.Deserialize('support staff serialized').AndReturn([support_user])

    self.mox.ReplayAll()
    self.assertTrue(auth.IsSupportStaff(support_user))
    self.mox.VerifyAll()

  def testIsSupportStaffWhenNotAdmin(self):
    """Test IsSupportStaff()."""
    support_user = 'support5@example.com'
    support_list = ['support1@example.com', 'support2@example.com']

    self.mox.StubOutWithMock(auth, 'users')
    self.mox.StubOutWithMock(auth.models.KeyValueCache, 'MemcacheWrappedGet')
    self.mox.StubOutWithMock(auth.util, 'Deserialize')
    auth.models.KeyValueCache.MemcacheWrappedGet(
        'support_staff', 'text_value').AndReturn('support staff serialized')
    auth.util.Deserialize('support staff serialized').AndReturn(support_list)

    self.mox.ReplayAll()
    self.assertFalse(auth.IsSupportStaff(support_user))
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()