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
"""panic module tests."""

import httplib
import logging


import mock
import stubout

from django.conf import settings
settings.configure()
from google.apputils import app
from google.apputils import basetest
import tests.appenginesdk
from simian.mac.admin import panic
from simian.mac.admin import xsrf
from tests.simian.mac.common import test


@mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
class AdminPanicTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    request = None
    response = mock.MagicMock()
    return panic.AdminPanic(request, response)

  def GetTestClassModule(self):
    return panic

  def testGet(self, _):
    """Test get()."""
    self.mox.StubOutWithMock(panic.common, 'IsPanicMode')
    self.mox.StubOutWithMock(self.c, 'IsAdminUser')
    self.mox.StubOutWithMock(self.c, 'Render')

    self.c.IsAdminUser().AndReturn(True)
    modes = []

    for mode in panic.common.PANIC_MODES:
      panic.common.IsPanicMode(mode).AndReturn(False)
      modes.append({'name': mode, 'enabled': False})

    self.c.Render(
        'panic.html', {'modes': modes, 'report_type': 'panic'})

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testPost(self, _):
    """Test post()."""
    mode = 'mode'
    enabled = 'enable'

    self.mox.StubOutWithMock(self.c, 'IsAdminUser')
    self.request.get('xsrf_token').AndReturn('token')
    self.c.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn('enable')
    self.request.get('verify').AndReturn(None)

    self.mox.StubOutWithMock(self.c, 'Render')
    self.c.Render(
        'panic_set_verify.html',
        {'mode': {'name': mode, 'enabled': enabled}, 'report_type': 'panic'})

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenVerifyEnable(self, _):
    """Test post()."""
    mode = 'mode'
    enabled = 'enable'

    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')
    self.mox.StubOutWithMock(self.c, 'IsAdminUser')

    self.request.get('xsrf_token').AndReturn('token')
    self.c.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, True).AndReturn(None)
    self.MockRedirect('/admin/panic')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenVerifyDisable(self, _):
    """Test post()."""
    mode = 'mode'
    enabled = 'disable'

    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')
    self.mox.StubOutWithMock(self.c, 'IsAdminUser')

    self.request.get('xsrf_token').AndReturn('token')
    self.c.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, False).AndReturn(None)
    self.MockRedirect('/admin/panic')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenInvalidMode(self, _):
    """Test post()."""
    mode = 'modezzz'
    enabled = 'enable'

    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')
    self.mox.StubOutWithMock(self.c, 'IsAdminUser')

    self.request.get('xsrf_token').AndReturn('token')
    self.c.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, True).AndRaise(ValueError)
    self.MockError(httplib.BAD_REQUEST)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenInvalidEnabled(self, _):
    """Test post()."""
    mode = 'mode'
    enabled = 'enablzzZZZe'

    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')
    self.mox.StubOutWithMock(self.c, 'IsAdminUser')

    self.request.get('xsrf_token').AndReturn('token')
    self.c.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    self.MockError(httplib.BAD_REQUEST)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
