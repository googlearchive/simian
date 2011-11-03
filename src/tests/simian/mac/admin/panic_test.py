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

"""panic module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from google.apputils import basetest
import mox
import stubout
from simian.mac.admin import panic
from simian.mac.common import test


class AdminPanicTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return panic.AdminPanic()

  def GetTestClassModule(self):
    return panic

  def MockTemplate(self, filename, html, args):
    if not hasattr(self, '_mock_template'):
      self.mox.StubOutWithMock(panic.os.path, 'join')
      self.mox.StubOutWithMock(panic.os.path, 'dirname')
      self.mox.StubOutWithMock(panic.template, 'render')
      self._mock_template = 1

    dirname = '/tmp'
    path = '%s/%s' % (dirname, filename)

    panic.os.path.dirname(panic.__file__).AndReturn(dirname)
    panic.os.path.join(dirname, filename).AndReturn(path)
    panic.template.render(path, args).AndReturn(html)

    return path

  def testGet(self):
    """Test get()."""
    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(panic.common, 'IsPanicMode')

    panic.auth.IsAdminUser().AndReturn(True)
    modes = []

    for mode in panic.common.PANIC_MODES:
      panic.common.IsPanicMode(mode).AndReturn(False)
      modes.append({'name': mode, 'enabled': False})

    self.MockTemplate('templates/panic.html', 'html', {'modes': modes})
    self.c.response.out.write('html').AndReturn(None)

    self.mox.ReplayAll()
    self.c.get()
    self.mox.VerifyAll()

  def testPost(self):
    """Test post()."""
    mode = 'mode'
    enabled = 'enable'

    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    panic.auth.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn('enable')
    self.request.get('verify').AndReturn(None)

    self.MockTemplate(
        'templates/panic_set_verify.html', 'html',
        {'mode': {'name': mode, 'enabled': enabled}})
    self.c.response.out.write('html')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenVerifyEnable(self):
    """Test post()."""
    mode = 'mode'
    enabled = 'enable'

    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')

    panic.auth.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, True).AndReturn(None)
    self.MockRedirect('/admin/panic')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenVerifyDisable(self):
    """Test post()."""
    mode = 'mode'
    enabled = 'disable'

    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')

    panic.auth.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, False).AndReturn(None)
    self.MockRedirect('/admin/panic')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenInvalidMode(self):
    """Test post()."""
    mode = 'modezzz'
    enabled = 'enable'

    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')

    panic.auth.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    panic.common.SetPanicMode(mode, True).AndRaise(ValueError)
    self.MockError(400)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostWhenInvalidEnabled(self):
    """Test post()."""
    mode = 'mode'
    enabled = 'enablzzZZZe'

    self.mox.StubOutWithMock(panic.auth, 'IsAdminUser')
    self.mox.StubOutWithMock(panic.common, 'SetPanicMode')

    panic.auth.IsAdminUser().AndReturn(True)
    self.request.get('mode').AndReturn(mode)
    self.request.get('enabled').AndReturn(enabled)
    self.request.get('verify').AndReturn(True)
    self.MockError(400)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()