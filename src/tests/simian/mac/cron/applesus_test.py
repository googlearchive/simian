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
"""applesus module tests."""

import datetime
import httplib
import logging
import urllib2
import urlparse

import mock
import stubout

from google.apputils import app
from google.apputils import basetest
from simian.mac import models
from tests.simian.mac.common import test
from simian.mac.cron import applesus


class AppleSusModuleTest(basetest.TestCase):

  def testCatalogsDictionary(self):
    """Test global CATALOGS value."""
    self.assertTrue(hasattr(applesus, 'CATALOGS'))
    self.assertTrue(type(applesus.CATALOGS) is type({}))

    for k in applesus.CATALOGS:
      # Key should be e.g. "10.6"
      self.assertTrue(k.startswith('10.'), 'CATALOGS key strange')
      p = urlparse.urlparse(applesus.CATALOGS[k])
      self.assertEqual(len(p), 6)
      self.assertEqual(p[0], 'https')
      self.assertTrue(p[1].endswith('.apple.com'))


class AppleSUSCatalogSyncTest(test.AppengineTest):

  def setUp(self):
    test.AppengineTest.setUp(self)

    self.stubs = stubout.StubOutForTesting()
    self.catalog_sync = applesus.AppleSUSCatalogSync()

  def tearDown(self):
    test.AppengineTest.tearDown(self)
    self.stubs.UnsetAll()

  @mock.patch.object(applesus.AppleSUSCatalogSync, '_UpdateCatalog')
  @mock.patch.object(applesus.urlfetch, 'fetch')
  def testUpdateCatalogIfChanged(
      self, fetch_mock, update_catalog_mock):
    """Test _UpdateCatalogIfChanged()."""
    deadline = 30
    xml = 'this is xml'
    catalog = mock.Mock()
    catalog.last_modified_header = 'lmh'

    headers = {'If-Modified-Since': catalog.last_modified_header}
    response = mock.Mock()
    response.status_code = httplib.OK
    response.content = xml
    response.headers = {'Last-Modified': 'hds'}
    fetch_mock.return_value = response

    url = applesus.CATALOGS.values()[0]

    self.assertTrue(self.catalog_sync._UpdateCatalogIfChanged(catalog, url))

    fetch_mock.assert_called_once_with(
        url, headers=headers, deadline=deadline,
        validate_certificate=True)
    update_catalog_mock.assert_called_once_with(
        xml, entity=catalog, last_modified='hds')

  @mock.patch.object(applesus.AppleSUSCatalogSync, '_UpdateCatalog')
  @mock.patch.object(applesus.urlfetch, 'fetch')
  def testUpdateCatalogIfChangedWhen304(
      self, fetch_mock, update_catalog_mock):
    """Test _UpdateCatalogIfChanged()."""
    deadline = 30
    catalog = mock.Mock()
    catalog.last_modified_header = 'lmh'

    headers = {'If-Modified-Since': catalog.last_modified_header}
    response = mock.Mock()
    response.status_code = httplib.NOT_MODIFIED
    fetch_mock.return_value = response

    url = applesus.CATALOGS.values()[0]

    self.assertFalse(self.catalog_sync._UpdateCatalogIfChanged(catalog, url))

    self.assertFalse(update_catalog_mock.called)
    fetch_mock.assert_called_once_with(
        url, headers=headers, deadline=deadline,
        validate_certificate=True)

  @mock.patch.object(applesus.AppleSUSCatalogSync, '_UpdateCatalog')
  @mock.patch.object(applesus.urlfetch, 'fetch')
  def testUpdateCatalogIfChangedWhenOtherStatusCode(
      self, fetch_mock, update_catalog_mock):
    """Test _UpdateCatalogIfChanged()."""
    deadline = 30
    catalog = mock.Mock()
    catalog.last_modified_header = 'lmh'
    headers = {'If-Modified-Since': catalog.last_modified_header}

    response = mock.Mock()
    response.status_code = httplib.NOT_FOUND
    fetch_mock.return_value = response

    url = applesus.CATALOGS.values()[0]

    self.assertRaises(
        applesus.urlfetch.DownloadError,
        self.catalog_sync._UpdateCatalogIfChanged,
        catalog, url)

    self.assertFalse(update_catalog_mock.called)
    fetch_mock.assert_called_once_with(
        url, headers=headers, deadline=deadline,
        validate_certificate=True)

  @mock.patch.object(applesus.applesus, 'DistFileDocument')
  @mock.patch.object(urllib2, 'urlopen')
  def testUpdateProductDataFromCatalog(self, urlopen_mock, dist_file_doc_mock):
    """Tests _UpdateProductDataFromCatalog()."""
    product_one_id = '1productid'
    product_one_url = 'http://example.com/%s.dist' % product_one_id
    product_one_package_url = 'http://example.com/%s.pkg' % product_one_id
    product_two_id = '2productid'
    product_two_url = 'http://example.com/%s.dist' % product_one_id
    product_two_package_url1 = 'http://example.com/%s-1.pkg' % product_two_id
    product_two_package_url2 = 'http://example.com/%s-2.pkg' % product_two_id
    product_two_dist = {
        'version': 'twover', 'title': 'twotitle', 'description': 'twodesc',
        'restart_required': False,
    }
    product_three_id = '3productid'
    product_three_url = 'http://example.com/%s.dist' % product_three_id
    product_three_package_url = 'http://example.com/%s.pkg' % product_three_id
    product_three_dist = {
        'version': 'threever', 'title': 'threetitle',
        'description': 'threedesc', 'restart_required': True,
    }
    onedate = datetime.datetime(2014, 10, 8, 20, 00, 00, 000000)
    twodate = datetime.datetime(2015, 10, 8, 12, 00, 00, 000000)
    threedate = datetime.datetime(2013, 10, 8, 3, 00, 00, 000000)
    catalog = {
        'Products': {
            product_one_id: {
                'Distributions': {'English': product_one_url},
                'PostDate': onedate,
                'Packages': [{'URL': [product_one_package_url]}],
            },
            product_two_id: {
                'Distributions': {'English': product_two_url},
                'PostDate': twodate,
                'Packages': [{'URL': product_two_package_url1},
                             {'URL': product_two_package_url2}],
            },
            product_three_id: {
                'Distributions': {'en': product_three_url},
                'PostDate': threedate,
                'Packages': [{'URL': product_three_package_url}],
            },
        }
    }

    mock_urllib_return = mock.Mock()
    mock_urllib_return.code = httplib.OK  # always return 200 for test.
    mock_urllib_return.read.side_effect = [product_two_dist, product_three_dist]
    urlopen_mock.return_value = mock_urllib_return

    # product_one; add to existing_products so it's skipped.
    models.AppleSUSProduct(product_id=product_one_id).put()

    # product_two
    mock_dfd_two = mock.Mock()
    for k, v in product_two_dist.iteritems():
      setattr(mock_dfd_two, k, v)
    # product_three
    mock_dfd_three = mock.Mock()
    for k, v in product_three_dist.iteritems():
      setattr(mock_dfd_three, k, v)

    dist_file_doc_mock.side_effect = [mock_dfd_two, mock_dfd_three]

    new_products = self.catalog_sync._UpdateProductDataFromCatalog(catalog)

    urlopen_mock.assert_has_calls(
        [mock.call(product_two_url), mock.call(product_three_url)],
        any_order=True)

    product_two = models.AppleSUSProduct.all().filter(
        'product_id =', product_two_id).fetch(1)[0]
    product_three = models.AppleSUSProduct.all().filter(
        'product_id =', product_three_id).fetch(1)[0]

    self.assertEqual(
        [product_two_id, product_three_id],
        [p.product_id for p in new_products])
    self.assertEqual(product_two.name, 'twotitle')
    self.assertEqual(product_two.apple_mtime, twodate)
    self.assertFalse(product_two.restart_required)
    self.assertTrue(product_two.unattended)
    self.assertEqual(product_two.package_urls,
                     [product_two_package_url1, product_two_package_url2])

    self.assertEqual(product_three.version, 'threever')
    self.assertEqual(product_three.description, 'threedesc')
    self.assertTrue(product_three.restart_required)
    self.assertFalse(product_three.unattended)
    self.assertEqual(
        product_three.package_urls, [product_three_package_url])

  def testDeprecateOrphanedProducts(self):
    """Tests _DeprecateOrphanedProducts() with deprecated & active products."""
    self.stubs.Set(
        applesus.applesus, 'OS_VERSIONS', frozenset(['10.9', '10.10', None]))
    self.stubs.Set(
        applesus.common, 'TRACKS', applesus.common.TRACKS + ['parseerror'])

    for os_version in applesus.applesus.OS_VERSIONS:
      for track in applesus.common.TRACKS + ['untouched']:
        if not os_version:
          continue
        key = '%s_%s' % (os_version, track)
        applesus.models.AppleSUSCatalog(
            key_name=key, plist='fooplist-%s' % key).put()

    test_products = {
        '10.8_unstable': ['product5', 'product6'],
        '10.8_testing': ['product5'],
        '10.8_stable': ['product5'],
        '10.8_untouched': ['product7'],
        '10.9_unstable': ['product5', 'product6'],
        '10.9_testing': ['product5'],
        '10.9_stable': ['product5'],
        '10.9_untouched': ['product7'],
        '10.10_unstable': ['product1'],
        '10.10_testing': ['product3', 'product4'],
        '10.10_stable': ['product3'],
        '10.10_untouched': ['product7'],
        '10.11_unstable': ['product1'],
        '10.11_testing': ['product3', 'product4'],
        '10.11_stable': ['product3'],
        '10.11_untouched': ['product7'],
    }
    for p in ['product2', 'product3', 'product7', 'deprecateme', 'andme']:
      models.AppleSUSProduct(product_id=p).put()

    def PlistStub(plist):
      m = mock.Mock()
      if 'parseerror' in plist:
        m.Parse.side_effect = applesus.plist.Error
      else:
        prefix = 'fooplist-'
        assert plist.startswith(prefix)
        m.get.return_value = test_products[plist[len(prefix):]]
      return m
    self.stubs.Set(applesus.plist, 'ApplePlist', PlistStub)

    out = self.catalog_sync._DeprecateOrphanedProducts()
    expected_deprecated = ['andme', 'deprecateme', 'product2']
    self.assertEqual(expected_deprecated, sorted(p.product_id for p in out))

    products = models.AppleSUSProduct.all().filter('deprecated =', False)
    self.assertEqual(
        ['product3', 'product7'], sorted(p.product_id for p in products))

  @mock.patch.object(applesus.AppleSUSCatalogSync, '_NotifyAdminsOfCatalogSync')
  @mock.patch.object(applesus.AppleSUSCatalogSync, '_DeprecateOrphanedProducts')
  @mock.patch.object(models.AdminAppleSUSProductLog, 'Log')
  @mock.patch.object(applesus.applesus, 'GenerateAppleSUSCatalog')
  def testProcessCatalogAndNotifyAdmins(
      self, generate_catalog_mock, log_mock, deprecate_products_mock,
      notify_mock):
    """Tests _ProcessCatalogAndNotifyAdmins()."""
    os_version = '10.7'
    mock_catalog = models.AppleSUSCatalog(plist='<plist></plist>')

    new_products = ['new1', 'new2']
    deprecated_products = ['old1', 'old2']

    deprecate_products_mock.return_value = deprecated_products

    with mock.patch.object(
        applesus.AppleSUSCatalogSync, '_UpdateProductDataFromCatalog',
        return_value=new_products):
      with mock.patch.object(applesus.plist, 'ApplePlist', autospec=True):
        self.catalog_sync._ProcessCatalogAndNotifyAdmins(
            mock_catalog, os_version)

    generate_catalog_mock.assert_called_once_with(
        os_version, applesus.common.UNSTABLE)

    notify_mock.assert_called_once_with(
        mock_catalog, new_products, deprecated_products)

    log_mock.assert_has_calls([
        mock.call(new_products, 'new for %s' % os_version),
        mock.call(deprecated_products, 'deprecated for %s' % os_version),
    ])


class AppleSUSAutoPromoteTest(test.AppengineTest):

  def setUp(self):
    test.AppengineTest.setUp(self)

    self.auto_promote = applesus.AppleSUSAutoPromote()

  @mock.patch.dict(
      applesus.settings.__dict__, {'HOUR_START': 9, 'HOUR_STOP': 15})
  def testGetWithWorkingHours(self):
    """Tests get() outside of working hours."""
    old = datetime.datetime(2014, 12, 10, 20, 00, 00, 000000)
    now = datetime.datetime(2016, 9, 12, 0, 00, 00, 000000)

    with mock.patch.object(datetime, 'datetime') as datetime_mock:
      datetime_mock.utcnow.return_value = old
      u1 = models.AppleSUSProduct(
          tracks=['unstable'], product_id='fooid1', manual_override=False)
      u1.put()
      u2 = models.AppleSUSProduct(
          tracks=['unstable', applesus.common.TESTING], product_id='fooid3',
          manual_override=False)
      u2.put()

    with mock.patch.object(
        applesus.AppleSUSCatalogSync, '_DeprecateOrphanedProducts'):
      self.auto_promote.get(now=now)

    u1 = models.AppleSUSProduct.get(u1.key())
    u2 = models.AppleSUSProduct.get(u2.key())
    self.assertTrue(
        applesus.common.TESTING not in u1.tracks)
    self.assertTrue(
        applesus.common.STABLE not in u2.tracks)

  @mock.patch.dict(
      applesus.settings.__dict__, {'HOUR_START': 9, 'HOUR_STOP': 17})
  @mock.patch.object(
      applesus.AppleSUSCatalogSync, '_DeprecateOrphanedProducts')
  def testGet(self, _):
    """Tests get() within working hours."""
    old = datetime.datetime(2014, 12, 10, 20, 00, 00, 000000)
    now = datetime.datetime(2016, 9, 10, 11, 00, 00, 000000)

    with mock.patch.object(datetime, 'datetime') as datetime_mock:
      datetime_mock.utcnow.return_value = old
      promote_testing_product = models.AppleSUSProduct(
          tracks=['unstable'], product_id='fooid', manual_override=False)
      promote_testing_product.put()

      promote_stable_product = models.AppleSUSProduct(
          tracks=['unstable', applesus.common.TESTING], product_id='fooid3',
          manual_override=False)
      promote_stable_product.put()

    toonew_product = models.AppleSUSProduct(
        tracks=['unstable'], product_id='fooid2', manual_override=False)
    toonew_product.put()

    with mock.patch.object(
        applesus.applesus, 'GenerateAppleSUSCatalogs') as generate_catalog_mock:
      with mock.patch.object(
          self.auto_promote, '_NotifyAdminsOfAutoPromotions') as notify_mock:
        self.auto_promote.get(now=now)

        notify_mock.assert_called_once()
        generate_catalog_mock.assert_has_calls(
            [mock.call(applesus.common.TESTING),
             mock.call(applesus.common.STABLE)], any_order=True)

    self.assertEqual(
        2, len(applesus.models.AdminAppleSUSProductLog.all().fetch(None)))

    promote_stable_product = models.AppleSUSProduct.get(
        promote_stable_product.key())
    promote_testing_product = models.AppleSUSProduct.get(
        promote_testing_product.key())
    toonew_product = models.AppleSUSProduct.get(toonew_product.key())

    self.assertTrue(
        applesus.common.TESTING in promote_testing_product.tracks)
    self.assertTrue(
        applesus.common.STABLE not in promote_testing_product.tracks)

    self.assertTrue(applesus.common.TESTING not in toonew_product.tracks)
    self.assertTrue(applesus.common.STABLE not in toonew_product.tracks)

    self.assertTrue(applesus.common.STABLE in promote_stable_product.tracks)


logging.disable(logging.ERROR)


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
