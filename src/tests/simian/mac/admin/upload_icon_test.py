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
import httplib
import os


import mock
import stubout
import webtest

from google.apputils import app
from google.apputils import resources
from google.apputils import basetest

from simian import settings
from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test


PLIST_FILE = 'simian/mac/common/testdata/testpackage.plist'


def GetTestData(rel_path):

  path = os.path.dirname(os.path.realpath(__file__))
  while os.path.basename(path) != 'tests':
    path = os.path.dirname(path)
  with open(os.path.join(path, rel_path)) as f:
    return f.read()


@mock.patch.object(auth, 'IsGroupMember', return_value=True)
@mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
class UploadIconModuleTest(test.AppengineTest):

  def setUp(self):
    super(UploadIconModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

    self.plist = GetTestData(PLIST_FILE)

  def testGCSBucketNotSet(self, *_):
    resp = self.testapp.post(
        '/admin/upload_icon/filename', status=httplib.NOT_FOUND)
    self.assertIn('GCS bucket is not set', resp.body)

  def testSuccess(self, *_):
    settings.ICONS_GCS_BUCKET = 'test'

    filename = 'testpackage.dmg'
    munki_name = 'testpackage'
    models.PackageInfo(
        key_name=filename, filename=filename,
        name=munki_name, _plist=self.plist).put()
    content = 'ICON_CONTETN'
    resp = self.testapp.post(
        '/admin/upload_icon/%s' % filename,
        upload_files=[('icon', '1.png', content)], status=httplib.FOUND)
    self.assertTrue(
        resp.headers['Location'].endswith('/admin/package/%s' % filename))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
