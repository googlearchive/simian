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
import datetime
import httplib
import uuid
import mock
import stubout

from google.appengine.ext import testbed

from google.apputils import app
from google.apputils import basetest

from simian.mac import models
from simian.mac.admin import main as gae_main
from simian.mac.admin import summary
from simian.mac.common import auth
from tests.simian.mac.common import test


class SummaryModuleTest(basetest.TestCase):

  def setUp(self):
    super(SummaryModuleTest, self).setUp()
    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.setup_env(
        overwrite=True,
        USER_EMAIL='zerocool@example.com',
        USER_ID='123',
        USER_IS_ADMIN='0',
        DEFAULT_VERSION_HOSTNAME='example.appspot.com')

    self.testbed.init_all_stubs()

    today = datetime.datetime.today()
    five_days_ago = today - datetime.timedelta(days=5)
    long_ago = today - datetime.timedelta(days=models.COMPUTER_ACTIVE_DAYS + 1)

    # computer in NYC
    models.Computer(
        active=True, hostname='host1', serial=str(uuid.uuid4()),
        uuid=str(uuid.uuid4()), owner='zaspire', client_version='2.3.1',
        os_version='10.11', site='NYC', track='stable',
        config_track='stable', connection_dates=[today],
        connections_on_corp=1, connections_off_corp=0, uptime=90000.0,
        root_disk_free=0, user_disk_free=10, preflight_datetime=today).put()

    # last active five days ago
    models.Computer(
        active=True, hostname='host10', serial=str(uuid.uuid4()),
        uuid=str(uuid.uuid4()), owner='zerocool', client_version='2.3.2',
        os_version='10.11', site='MTV', track='stable',
        config_track='stable', connection_dates=[five_days_ago],
        connections_on_corp=1, connections_off_corp=1, uptime=90000.0,
        root_disk_free=0, user_disk_free=10,
        preflight_datetime=five_days_ago).put()

    # inactive computer in MTV
    models.Computer(
        active=False, hostname='host2', serial=str(uuid.uuid4()),
        uuid=str(uuid.uuid4()), owner='zerocool', client_version='2.3.1',
        os_version='10.11', site='MTV', track='stable',
        config_track='stable', connection_dates=[long_ago],
        connections_on_corp=1, connections_off_corp=1, uptime=90000.0,
        root_disk_free=0, user_disk_free=10,
        preflight_datetime=long_ago).put()

    # track unstable
    models.Computer(
        active=True, hostname='xyz-macbook', serial=str(uuid.uuid4()),
        uuid=str(uuid.uuid4()), owner='zerocool', client_version='2.3.3',
        os_version='10.10', site='MTV', track='unstable',
        config_track='unstable', connection_dates=[today],
        connections_on_corp=0, connections_off_corp=100, uptime=90000.0,
        root_disk_free=0, user_disk_free=10, preflight_datetime=today).put()

    reports_cache = models.ReportsCache()
    trending = {
        'success': {'packages': [('emacs', 10, 61.1)], 'total': 100},
        'failure': {'packages': [('vim', 10, 61.1)], 'total': 50},
        }

    reports_cache.SetTrendingInstalls(1, trending)
    trending['failure']['packages'].append(('office', 132, 99.9))
    reports_cache.SetTrendingInstalls(24, trending)

  def tearDown(self):
    super(SummaryModuleTest, self).tearDown()
    self.testbed.deactivate()

  def testGetComputerSummary(self):
    computers = models.Computer.all().filter('active =', True).fetch(500)
    s = summary.PrepareComputerSummaryForTemplate(
        summary.GetComputerSummary(computers))
    self.assertEqual(2, dict(s['sites_histogram'])['MTV'])
    self.assertEqual(2, dict(s['os_versions'])['10.11'])
    self.assertEqual(1, dict(s['client_versions'])['2.3.3'])
    self.assertEqual(1, s['tracks']['stable'][1])
    self.assertEqual(2, s['conns_on_corp'])
    self.assertEqual(2, s['active'][1])
    self.assertEqual(3, s['active'][14])
    self.assertAlmostEqual(98.0582, s['conns_off_corp_percent'], 3)

  @mock.patch.dict(summary.settings.__dict__, {
      'ALLOW_SELF_REPORT': False, 'AUTH_DOMAIN': 'example.com'})
  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  def testAccessDenied(self, *_):
    resp = gae_main.app.get_response('/admin/')
    self.assertEqual(httplib.FORBIDDEN, resp.status_int)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(summary.Summary, 'Render')
  @mock.patch.dict(summary.settings.__dict__, {'CLIENT_SITE_ENABLED': False})
  def testOwnerSummary(self, render, *_):
    resp = gae_main.app.get_response(
        '/admin/?filter-type=owner&filter=zerocool')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)

    self.assertFalse(params['self_report'])
    self.assertEqual('search', params['report_type'])
    self.assertEqual(2, len(params['computers']))
    self.assertEqual(('MTV', 2), params['summary']['sites_histogram'][0])
    self.assertAlmostEqual(
        99.0196, params['summary']['conns_off_corp_percent'], 3)

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(summary.Summary, 'Render')
  @mock.patch.dict(summary.settings.__dict__, {'CLIENT_SITE_ENABLED': False})
  def testSiteSummary(self, render, *_):
    resp = gae_main.app.get_response(
        '/admin/?filter-type=site&filter=MTV')
    self.assertEqual(httplib.OK, resp.status_int)

    params = test.GetArgFromCallHistory(render, arg_index=1)

    self.assertEqual('search', params['report_type'])
    self.assertEqual(2, len(params['computers']))

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  def testOneResultSummaryRedirect(self, *_):
    resp = gae_main.app.get_response(
        '/admin/?filter-type=hostname&filter=host1')
    self.assertEqual(httplib.FOUND, resp.status_int)

    self.assertTrue('/admin/host/' in resp.headers['Location'])

  @mock.patch.object(auth, 'IsGroupMember', return_value=False)
  @mock.patch.dict(summary.settings.__dict__, {
      'ALLOW_SELF_REPORT': True, 'AUTH_DOMAIN': 'example.com'})
  @mock.patch.object(summary.Summary, 'Render')
  @mock.patch.dict(summary.settings.__dict__, {'CLIENT_SITE_ENABLED': False})
  def testSelfReport(self, render, *_):
    resp = gae_main.app.get_response('/admin/')

    self.assertEqual(httplib.OK, resp.status_int)
    params = test.GetArgFromCallHistory(render, arg_index=1)
    self.assertTrue(params['self_report'])

    self.assertEqual('owner', params['search_type'])
    self.assertEqual('zerocool', params['search_term'])

    self.assertEqual(2, len(params['computers']))
    self.assertEqual('zerocool', params['computers'][0].owner)
    self.assertEqual('zerocool', params['computers'][1].owner)


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
