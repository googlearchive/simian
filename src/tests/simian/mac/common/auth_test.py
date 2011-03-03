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

    user = 'joe'
    auth.users.get_current_user().AndReturn(None)  # 1
    auth.users.get_current_user().AndReturn(user) # 2
    auth.users.get_current_user().AndReturn(user) # 3
    auth.users.is_current_user_admin().AndReturn(True)  # 3
    auth.users.get_current_user().AndReturn(user)  # 4
    auth.users.is_current_user_admin().AndReturn(True)  # 4

    self.mox.ReplayAll()
    # 1
    self.assertRaises(auth.NotAuthenticated, auth.DoUserAuth)
    # 2
    self.assertEqual(user, auth.DoUserAuth())
    # 3
    auth.DoUserAuth(is_admin=True)
    # 4
    self.assertRaises(auth.IsAdminMismatch, auth.DoUserAuth, is_admin=False)
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


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()