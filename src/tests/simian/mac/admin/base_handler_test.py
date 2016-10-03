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
import httplib


import webapp2
import webtest

from google.apputils import app
from google.apputils import basetest

from simian.mac import admin
from simian.mac.admin import xsrf
from tests.simian.mac.common import test


class MockHandler(admin.AdminHandler):
  """Mock handler."""

  def get(self):
    self.response.write(xsrf.XsrfTokenGenerate('mock'))

  @admin.AdminHandler.XsrfProtected('mock')
  def post(self):
    self.response.write('Content.')


class BaseHandlerTest(test.AppengineTest):

  def setUp(self):
    super(BaseHandlerTest, self).setUp()
    webapp = webapp2.WSGIApplication([('/', MockHandler)])
    self.testapp = webtest.TestApp(webapp)

  def testClickjackingPrevention(self):
    resp = self.testapp.get('/')
    self.assertEqual(
        'frame-ancestors \'self\'',
        resp.headers[admin.CONTENT_SECURITY_POLICY_HEADER])

  def testXsrfProtection(self):
    resp = self.testapp.get('/', status=httplib.OK)

    self.testapp.post('/', {'xsrf_token': resp.body}, status=httplib.OK)


def main(_):
  basetest.main()


if __name__ == '__main__':
  app.run()
