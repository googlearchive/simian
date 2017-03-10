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
"""maint module tests."""

import datetime
import httplib
import logging
import mock
import stubout
import webtest

from google.appengine.ext import blobstore
from google.appengine.ext import deferred
from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import resources
from google.apputils import basetest
from simian.mac import models
from tests.simian.mac.common import test
from simian.mac.cron import maintenance as maint
from simian.mac.cron.main import app as gae_app


class AuthSessionCleanupTest(basetest.TestCase):

  def setUp(self):
    super(AuthSessionCleanupTest, self).setUp()
    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='user@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()
    self.testapp = webtest.TestApp(gae_app)

  def tearDown(self):
    super(AuthSessionCleanupTest, self).tearDown()
    self.testbed.deactivate()

  def testGet(self):
    """Test get()."""
    valid_session_name = 'cn_2'
    models.AuthSession(
        key_name='t_1', state='OK',
        mtime=datetime.datetime.fromtimestamp(0)).put()
    models.AuthSession(
        key_name='cn_1', state=None,
        mtime=datetime.datetime.fromtimestamp(0)).put()
    models.AuthSession(
        key_name=valid_session_name, mtime=datetime.datetime.utcnow()).put()
    self.testapp.get('/cron/maintenance/authsession_cleanup')

    taskqueue_stub = self.testbed.get_stub(testbed.TASKQUEUE_SERVICE_NAME)
    tasks = taskqueue_stub.get_filtered_tasks()

    for i in range(len(tasks)):
      deferred.run(tasks[i].payload)

    sessions = models.AuthSession.all().fetch(10)

    self.assertEqual(1, len(sessions))
    self.assertEqual(valid_session_name, sessions[0].key().name())


class UpdateAverageInstallDurationsTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return maint.UpdateAverageInstallDurations()

  def GetTestClassModule(self):
    return maint

  def _testGetUpdatedDescriptionExistingDescWithAvgDuration(self):
    """Test _GetUpdatedDescription() with desc and avg duration text."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = 'Foo Bar\n\n%s' % avg_duration_text % (5490, 120)
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = 'Foo Bar\n\n%s' % avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def _testGetUpdatedDescriptionExistingDescWithoutAvgDuration(self):
    """Test _GetUpdatedDescription() with desc lacking avg durations text."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = 'Foo Bar'
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = 'Foo Bar\n\n%s' % avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def _testGetUpdatedDescriptionEmpty(self):
    """Test _GetUpdatedDescription() with an empty desc."""
    avg_duration_text = maint.models.PackageInfo.AVG_DURATION_TEXT
    old_desc = ''
    duration_dict = {'duration_count': 6523, 'duration_seconds_avg': 117}
    expected_desc = avg_duration_text % (6523, 117)

    new_desc = self.c._GetUpdatedDescription(duration_dict, old_desc)
    self.assertEqual(new_desc, expected_desc)

  def testGet(self):
    """Test get()."""
    plist_file = (
        'simian/mac/common/testdata/testpackage.plist')
    plist = open('src/tests/' + plist_file).read()
    pkg1_munki_name = 'testpackage-1'
    models.PackageInfo(filename='filename1', _plist=plist).put()

    with mock.patch.object(models.ReportsCache, 'GetInstallCounts') as m:
      m.return_value = ({
          pkg1_munki_name: {
              'install_count': 3,
              'applesus': True,
              'duration_count': 2,
              'duration_total_seconds': 50,
              'duration_seconds_avg': int((50)/2),
          }
      }, 0)
      resp = gae_app.get_response(
          '/cron/maintenance/update_avg_install_durations')
    self.assertEqual(httplib.OK, resp.status_int)

    pkg_info = models.PackageInfo().all().fetch(1)[0]
    self.assertEqual(
        'test package\n\n'
        '2 users have installed this with an average duration of 25 seconds.',
        pkg_info.plist['description'])


class VerifyPackagesCleanupTest(test.AppengineTest):

  def testGet(self):
    """Test get()."""
    self.testapp = webtest.TestApp(gae_app)
    blobstore_stub = self.testbed.get_stub(testbed.BLOBSTORE_SERVICE_NAME)
    mail_stub = self.testbed.get_stub('mail')

    goodblob_key = 'good'
    blobstore_stub.CreateBlob(goodblob_key, 'content')
    blobstore_stub.CreateBlob('to_be_deleted', '123B')

    filename_bad = 'missing_blob'

    models.PackageInfo(
        filename=filename_bad, mtime=datetime.datetime(1970, 1, 1)).put(
            avoid_mtime_update=True)
    models.PackageInfo(
        filename='good', mtime=datetime.datetime(1970, 1, 1),
        blobstore_key=goodblob_key).put(avoid_mtime_update=True)

    self.testapp.get('/cron/maintenance/verify_packages')
    self.RunAllDeferredTasks()

    self.assertEqual(1, len(mail_stub.get_sent_messages()))
    mail = mail_stub.get_sent_messages()[0]
    self.assertEqual('Package is lacking a file: missing_blob', mail.subject)

    keys = []
    for b in blobstore.BlobInfo.all():
      keys.append(str(b.key()))
    self.assertEqual([goodblob_key], keys)


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
