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
import datetime
import httplib


import mock
import stubout
import webtest

from google.apputils import basetest

from simian import settings
from simian.mac import admin
from simian.mac import models
from simian.mac.admin import applesus
from simian.mac.admin import main as gae_main
from simian.mac.admin import xsrf
from simian.mac.common import auth
from tests.simian.mac.common import test


class ApplesusModuleTest(test.AppengineTest):

  def setUp(self):
    super(ApplesusModuleTest, self).setUp()
    self.testapp = webtest.TestApp(gae_main.app)

  @mock.patch.object(auth, 'IsAdminUser', return_value=False)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testPostAccessDenied(self, *_):
    self.testapp.post('/admin/applesus', status=httplib.FORBIDDEN)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  @mock.patch.object(applesus.applesus, 'GenerateAppleSUSCatalogs')
  def testPostCatalogGeneration(self, generate_catalog_mock, *_):
    self.testapp.post('/admin/applesus', {
        'regenerate-catalogs': 1,
        'tracks': 'stable',
    })

    generate_catalog_mock.assert_called_once_with(tracks=['stable'], delay=1)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testChangeProduct(self, *_):
    settings.EMAIL_ON_EVERY_CHANGE = True

    product_id = 'pid'
    models.AppleSUSProduct(key_name=product_id, product_id=product_id).put()

    self.testapp.post('/admin/applesus/product/' + product_id, {
        'enabled': 1,
        'track': 'stable',
    }, status=httplib.OK)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    self.assertEqual(['stable'], product.tracks)

    self.RunAllDeferredTasks()

    mail_stub = self.testbed.get_stub('mail')
    messages = mail_stub.get_sent_messages()

    self.assertEqual(1, len(messages))
    self.assertEqual('admin@example.com', messages[0].to)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testChangeProductManualOverride(self, *_):
    product_id = 'pid'
    models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, manual_override=False).put()

    self.testapp.post('/admin/applesus/product/' + product_id, {
        'manual_override': 1,
    }, status=httplib.OK)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    self.assertTrue(product.manual_override)

    self.RunAllDeferredTasks()

    mail_stub = self.testbed.get_stub('mail')
    messages = mail_stub.get_sent_messages()

    self.assertEqual(1, len(messages))

    self.assertEqual(1, len(models.AdminAppleSUSProductLog.all().fetch(None)))

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testChangeProductUnattended(self, *_):
    product_id = 'pid'
    models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, unattended=False).put()

    self.testapp.post('/admin/applesus/product/' + product_id, {
        'unattended': 1,
    }, status=httplib.OK)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    self.assertTrue(product.unattended)

    self.RunAllDeferredTasks()

    mail_stub = self.testbed.get_stub('mail')
    messages = mail_stub.get_sent_messages()

    self.assertEqual(1, len(messages))

    self.assertEqual(1, len(models.AdminAppleSUSProductLog.all().fetch(None)))

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testChangeProductForceInstallToday(self, *_):
    product_id = 'pid'
    models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, manual_override=False).put()

    force_install_after_date = datetime.datetime.now()

    self.testapp.post('/admin/applesus/product/' + product_id, {
        'force_install_after_date': datetime.datetime.strftime(
            force_install_after_date, '%Y-%m-%d %H:%M'),
    }, status=httplib.BAD_REQUEST)

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(xsrf, 'XsrfTokenValidate', return_value=True)
  def testChangeProductForceInstall(self, *_):
    product_id = 'pid'
    models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, manual_override=False).put()

    force_install_after_date = (datetime.datetime.now() +
                                datetime.timedelta(days=4))

    self.testapp.post('/admin/applesus/product/' + product_id, {
        'force_install_after_date': datetime.datetime.strftime(
            force_install_after_date, '%Y-%m-%d %H:%M'),
    }, status=httplib.OK)

    product = models.AppleSUSProduct.get_by_key_name(product_id)
    self.assertEquals(
        datetime.datetime.strftime(
            force_install_after_date, '%Y-%m-%dT%H:%M:00Z'),
        product.force_install_after_date_str)

    self.RunAllDeferredTasks()

    mail_stub = self.testbed.get_stub('mail')
    messages = mail_stub.get_sent_messages()

    self.assertEqual(1, len(messages))
    self.assertEqual(1, len(models.AdminAppleSUSProductLog.all().fetch(None)))

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.AdminHandler, 'Render')
  def testDisplayMain(self, render_mock, _):
    product_id = 'pid'
    models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, tracks=['unstable']).put()

    self.testapp.get('/admin/applesus/', status=httplib.OK)

    args = test.GetArgFromCallHistory(render_mock, arg_index=1)

    self.assertEqual(1, len(args['products']))
    self.assertLess(
        args['products'][0].stable_promote_date,
        (datetime.datetime.now() + datetime.timedelta(days=60)).date())

  @mock.patch.object(auth, 'IsAdminUser', return_value=True)
  @mock.patch.object(admin.AdminHandler, 'Render')
  def testDisplayUpdateLogs(self, render_mock, _):
    product_id = 'pid'
    p = models.AppleSUSProduct(
        key_name=product_id, product_id=product_id, tracks=['unstable'])
    p.put()
    models.AdminAppleSUSProductLog.Log(p, 'action description')

    self.testapp.get(
        '/admin/applesus/logs', {'product_id': product_id}, status=httplib.OK)

    args = test.GetArgFromCallHistory(render_mock, arg_index=1)
    self.assertEqual(1, len(args['logs']))
    self.assertEqual(product_id, args['product_id'])


if __name__ == '__main__':
  basetest.main()
