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
"""Apple SUS module tests."""

import datetime
import plistlib

import mox
import stubout

import tests.appenginesdk
from simian.mac.common import datastore_locks
from google.apputils import app
from google.apputils import basetest
from simian.mac.common import applesus
from simian.mac.common import gae_util
from tests.simian.mac.common import test


class AppleModuleTest(mox.MoxTestBase, test.AppengineTest):

  def setUp(self):
    test.AppengineTest.setUp(self)
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()

  def tearDown(self):
    test.AppengineTest.tearDown(self)
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def _GetTestData(self, filename):
    f = open('./src/tests/simian/mac/common/testdata/%s' % filename)
    buf = []
    while 1:
      s = f.read()
      if not s:
        break
      else:
        buf.append(s)
    f.close()
    return ''.join(buf)


  def testGenerateAppleSUSCatalogWhereUntouchedDoesNotExist(self):
    """Test GenerateAppleSUSCatalog() where untouched catalog does not exist."""
    os_version = 'foo-version'
    track = 'foo'

    self.mox.StubOutWithMock(applesus.models.AppleSUSCatalog, 'get_by_key_name')

    applesus.models.AppleSUSCatalog.get_by_key_name(
        '%s_untouched' % os_version).AndReturn(None)

    self.mox.ReplayAll()
    catalog, new_plist = applesus.GenerateAppleSUSCatalog(os_version, track)
    self.assertEqual(None, catalog)
    self.assertEqual(None, new_plist)
    self.mox.VerifyAll()

  def testGenerateAppleSUSCatalog(self):
    """Test GenerateAppleSUSCatalog()."""
    catalog_xml = self._GetTestData('applesus.sucatalog')
    track = 'testing'
    os_version = '10.6'

    product_one = self.mox.CreateMockAnything()
    product_one.product_id = 'ID1'
    product_two = self.mox.CreateMockAnything()
    product_two.product_id = 'ID3'
    products = [product_one, product_two]

    mock_catalog_obj = self.mox.CreateMockAnything()
    mock_catalog_obj.plist = catalog_xml
    mock_query = self.mox.CreateMockAnything()
    mock_new_catalog_obj = self.mox.CreateMockAnything()

    self.mox.StubOutWithMock(applesus.models.AppleSUSCatalog, 'get_by_key_name')
    self.mox.StubOutWithMock(applesus.models, 'AppleSUSCatalog')
    self.mox.StubOutWithMock(applesus.models.AppleSUSProduct, 'AllActive')

    applesus.models.AppleSUSCatalog.get_by_key_name(
        '%s_untouched' % os_version).AndReturn(mock_catalog_obj)

    applesus.models.AppleSUSProduct.AllActive().AndReturn(mock_query)
    mock_query.filter('tracks =', track).AndReturn(products)

    mock_datetime = self.mox.CreateMockAnything()
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    now_str = '2010-09-02-19-30-21'
    mock_datetime.utcnow().AndReturn(utcnow)
    applesus.models.AppleSUSCatalog(
        key_name='backup_%s_%s_%s' % (os_version, track, now_str)).AndReturn(
            mock_new_catalog_obj)
    mock_new_catalog_obj.put().AndReturn(None)

    applesus.models.AppleSUSCatalog(
        key_name='%s_%s' % (os_version, track)).AndReturn(mock_new_catalog_obj)
    mock_new_catalog_obj.put().AndReturn(None)

    lock_name = 'lock_name'
    lock = datastore_locks.DatastoreLock(lock_name)
    lock.Acquire()

    self.mox.ReplayAll()
    _, new_plist = applesus.GenerateAppleSUSCatalog(
        os_version, track, mock_datetime, catalog_lock=lock)
    self.assertTrue('ID1' in new_plist['Products'])
    self.assertTrue('ID2' not in new_plist['Products'])
    self.assertTrue('ID3' in new_plist['Products'])
    self.assertTrue('ID4' not in new_plist['Products'])
    self.mox.VerifyAll()

    self.assertFalse(gae_util.LockExists(lock_name))

  def testGetAutoPromoteDateTesting(self):
    """Test GetAutoPromoteDate() for testing track."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.mtime = datetime.datetime(2011, 7, 22, 00, 00, 00)
    applesus_product.manual_override = False
    applesus_product.tracks = [applesus.common.UNSTABLE]
    auto_promote_date = datetime.date(2011, 7, 26)

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.TESTING, applesus_product)
    self.assertEqual(d, auto_promote_date)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateTestingSaturday(self):
    """Test GetAutoPromoteDate() for testing track."""
    applesus_product = self.mox.CreateMockAnything()
    # 2011-07-18 + AUTO_PROMOTE_PHASE_DAYS_MAP['testing'] is a Saturday.
    applesus_product.mtime = datetime.datetime(2011, 7, 19, 00, 00, 00)
    applesus_product.manual_override = False
    applesus_product.tracks = [applesus.common.UNSTABLE]
    # So don't promote on 2011-07-18 + AUTO_PROMOTE_PHASE_DAYS_MAP['testing'],
    # instead delay until the following Monday.
    auto_promote_date = datetime.date(2011, 7, 25)

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.TESTING, applesus_product)
    self.assertEqual(d, auto_promote_date)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateStable(self):
    """Test GetAutoPromoteDate() for stable track."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.mtime = datetime.datetime(2011, 7, 22, 00, 00, 00)
    applesus_product.manual_override = False
    applesus_product.tracks = [
        applesus.common.UNSTABLE, applesus.common.TESTING]
    auto_promote_date = datetime.date(2011, 8, 03)

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.STABLE, applesus_product)
    self.assertEqual(d, auto_promote_date)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateStableButNotYetInTesting(self):
    """Test GetAutoPromoteDate() for stable where product not yet in testing."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.mtime = datetime.datetime(2011, 7, 22, 00, 00, 00)
    applesus_product.manual_override = False
    applesus_product.tracks = [applesus.common.UNSTABLE]
    auto_promote_date = datetime.date(2011, 8, 03)

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.STABLE, applesus_product)
    self.assertEqual(d, auto_promote_date)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateStableButNotYetInTestingButTestingDelayed(self):
    """Test GetAutoPromoteDate() for stable where product not yet in testing."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.mtime = datetime.datetime(2011, 7, 26, 00, 00, 00)
    applesus_product.manual_override = False
    applesus_product.tracks = [applesus.common.UNSTABLE]
    auto_promote_date = datetime.date(2011, 8, 10)

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.STABLE, applesus_product)
    self.assertEqual(d, auto_promote_date)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateOverride(self):
    """Test GetAutoPromoteDate() for a product that has manual_override set."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.manual_override = True

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.TESTING, applesus_product)
    self.assertEqual(d, None)
    self.mox.VerifyAll()

  def testGetAutoPromoteDateNotInUnstable(self):
    """Test GetAutoPromoteDate() for a product that's not in unstable."""
    applesus_product = self.mox.CreateMockAnything()
    applesus_product.manual_override = False
    applesus_product.tracks = []

    self.mox.ReplayAll()
    d = applesus.GetAutoPromoteDate(applesus.common.TESTING, applesus_product)
    self.assertEqual(d, None)
    self.mox.VerifyAll()

  def testGetNextWeekdayDate(self):
    """Tests GetNextWeekdayDate().

    Tested dates are in the past, current day, days and even weeks in future.
    """
    dates = [
        (datetime.date(2011, 7, 21), datetime.date(2011, 7, 27)),
        (datetime.date(2011, 7, 22), datetime.date(2011, 7, 27)),
        (datetime.date(2011, 7, 26), datetime.date(2011, 7, 27)),
        (datetime.date(2011, 7, 27), datetime.date(2011, 7, 27)),
        (datetime.date(2011, 7, 28), datetime.date(2011, 8, 03)),
        (datetime.date(2011, 8, 04), datetime.date(2011, 8, 10)),
        (datetime.date(2011, 10, 13), datetime.date(2011, 10, 19)),
    ]

    self.mox.ReplayAll()
    for date in dates:
      self.assertEqual(
          applesus._GetNextWeekdayDate(applesus.WED, min_date=date[0]), date[1])
    self.mox.VerifyAll()


class DistFileDocumentTest(mox.MoxTestBase):

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.stubs = stubout.StubOutForTesting()
    self.dfd = applesus.DistFileDocument()

  def tearDown(self):
    self.mox.UnsetStubs()
    self.stubs.UnsetAll()

  def testReset(self):
    """Test Reset()."""
    self.dfd._installer_script = 'erase'
    self.dfd.Reset()
    self.assertEqual(self.dfd._installer_script, {})

  def testParseInstallerScriptString(self):
    """Test _ParseInstallerScriptString()."""
    t = [
        ['"K"="V";\n', {'K': 'V'}],
        ['"K"=\'V\';\n', {'K': 'V'}],
        ['"K"="V";\n\n\n"K2"="V2";\n', {'K': 'V', 'K2': 'V2'}],
        ['"K"="V";\n\n\n"K2"="V2\nV3";\n', {'K': 'V', 'K2': 'V2\nV3'}],
        # an invalid line disrupts the parser
        ['"K"=;\n"K2"="V2"\n', {}],
        # nested quotes
        ['"K"=\'Hello "there"\';', {'K': 'Hello "there"'}],
        ]

    for i, o in t:
      self.assertEqual(self.dfd._ParseInstallerScriptString(i), o)

  def testLoadDocument(self):
    """Test LoadDocument."""
    doc = self.mox.CreateMockAnything()
    docstr = 'xmldoc'

    self.mox.StubOutWithMock(applesus.minidom, 'parseString')
    self.mox.StubOutWithMock(self.dfd, '_ParseInstallerScriptString')

    applesus.minidom.parseString(docstr).AndReturn(doc)
    doc.getElementsByTagName('localization').AndReturn(doc)
    doc.__getitem__(0).AndReturn(doc)
    doc.getElementsByTagName('strings').AndReturn(doc)
    doc.__getitem__(0).AndReturn(doc)
    doc.childNodes = [doc]
    doc.nodeValue = 'hello'

    self.dfd._ParseInstallerScriptString('hello').AndReturn({'foo': True})

    self.mox.ReplayAll()
    self.dfd.LoadDocument(docstr)
    self.assertEqual(self.dfd._installer_script, {'foo': True})
    self.mox.VerifyAll()


class GenerateAppleSUSMetadataCatalogTest(mox.MoxTestBase):

  def testNominal(self):
    mock_product1 = applesus.models.AppleSUSProduct(
        product_id='ID1', name='Any Widget', version='2.0', unattended=True)
    mock_product2 = applesus.models.AppleSUSProduct(
        product_id='ID2', name='Any Widget 2', version='2.1',
        force_install_after_date=datetime.datetime.utcnow())

    mock_query = self.mox.CreateMockAnything()
    self.mox.StubOutWithMock(applesus.models, 'AppleSUSProduct')

    applesus.models.AppleSUSProduct.AllActive().AndReturn(mock_query)
    mock_query.filter('unattended =', True).AndReturn([mock_product1])
    applesus.models.AppleSUSProduct.AllActive().AndReturn(mock_query)
    mock_query.filter('force_install_after_date !=', None).AndReturn(
        [mock_product2])

    mock_cat = applesus.models.AppleSUSCatalog()
    self.mox.StubOutWithMock(mock_cat, 'put')
    self.mox.StubOutWithMock(applesus.models, 'Catalog')
    applesus.models.Catalog(key_name=mox.IsA(str)).AndReturn(mock_cat)
    mock_cat.put()

    self.mox.StubOutWithMock(applesus.models.Catalog, 'DeleteMemcacheWrap')
    applesus.models.Catalog.DeleteMemcacheWrap(
        'apple_update_metadata', prop_name='plist_xml').AndReturn(None)

    self.mox.ReplayAll()
    result = applesus.GenerateAppleSUSMetadataCatalog()
    self.mox.VerifyAll()

    self.assertEquals(mock_cat, result)
    plist = plistlib.readPlistFromString(mock_cat.plist)
    self.assertEquals(2, len(plist))
    self.assertTrue(all(isinstance(x, dict) for x in plist))
    self.assertTrue(all('installer_type' in x for x in plist))
    self.assertTrue(all('name' in x for x in plist))
    self.assertTrue(all(
        'unattended_install' in x for x in plist if x['name'] == 'ID1'))
    self.assertTrue(all(
        'force_install_after_date' in x for x in plist if x['name'] == 'ID2'))


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
