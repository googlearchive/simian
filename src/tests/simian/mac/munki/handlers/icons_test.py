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
import base64
import httplib


import mock
import stubout
import webtest

import cloudstorage as gcs
from google.apputils import app
from google.apputils import basetest

from simian import settings
from simian.mac.common import auth
from tests.simian.mac.common import test
from simian.mac.urls import app as gae_app


@mock.patch.object(auth, 'DoAnyAuth')
class IconsModuleTest(test.AppengineTest):

  def setUp(self):
    super(IconsModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_app)

  def testNotFound(self, *_):
    settings.ICONS_GCS_BUCKET = 'test'
    self.testapp.get('/icons/filename.png', status=httplib.NOT_FOUND)

  def testSuccess(self, *_):
    settings.ICONS_GCS_BUCKET = 'test'

    content = 'IMAGE_CONTENT'
    with gcs.open(
        '/test/%s.png' % base64.urlsafe_b64encode('filename'), 'w') as f:
      f.write(content)
    resp = self.testapp.get('/icons/filename.png', status=httplib.OK)

    self.assertEqual(content, resp.body)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
