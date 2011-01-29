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

"""Munki common module tests."""



import datetime
import logging
logging.basicConfig(filename='/dev/null')

import tests.appenginesdk
from google.apputils import app
from simian.mac.common import test
from simian.mac.munki import common

logging.basicConfig(filename='/dev/null')

class CommonModuleTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return self.mox.CreateMockAnything()

  def GetTestClassModule(self):
    return common

  def _MockObtainLock(self, name, obtain=True):
    if not hasattr(self, '_mock_obtain_lock'):
      self.mox.StubOutWithMock(common, 'ObtainLock')
      self._mock_obtain_lock = True
    common.ObtainLock(name).AndReturn(obtain)

  def _MockReleaseLock(self, name):
    if not hasattr(self, '_mock_release_lock'):
      self.mox.StubOutWithMock(common, 'ReleaseLock')
      self._mock_release_lock = True
    common.ReleaseLock(name).AndReturn(None)

  def testObtainLock(self):
    """Test ObtainLock()."""
    lock = 'foo'
    self.mox.StubOutWithMock(common, 'memcache')
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(1)
    self.mox.ReplayAll()
    self.assertTrue(common.ObtainLock(lock))
    self.mox.VerifyAll()

  def testObtainLockWhenTimeoutTrue(self):
    """Test ObtainLock()."""
    lock = 'foo'
    self.mox.StubOutWithMock(common, 'memcache')
    self.mox.StubOutWithMock(common.time, 'sleep')
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    common.time.sleep(1).AndReturn(None)
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(1)
    self.mox.ReplayAll()
    self.assertTrue(common.ObtainLock(lock, timeout=1))
    self.mox.VerifyAll()

  def testObtainLockWhenTimeoutFalse(self):
    """Test ObtainLock()."""
    lock = 'foo'
    self.mox.StubOutWithMock(common, 'memcache')
    self.mox.StubOutWithMock(common.time, 'sleep')
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    common.time.sleep(1).AndReturn(None)
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    common.time.sleep(1).AndReturn(None)
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    common.time.sleep(1).AndReturn(None)
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    self.mox.ReplayAll()
    self.assertFalse(common.ObtainLock(lock, timeout=3))
    self.mox.VerifyAll()

  def testObtainLockWhenFail(self):
    """Test ObtainLock()."""
    lock = 'foo'
    self.mox.StubOutWithMock(common, 'memcache')
    common.memcache.incr('lock_%s' % lock, initial_value=0).AndReturn(2)
    self.mox.ReplayAll()
    self.assertFalse(common.ObtainLock(lock))
    self.mox.VerifyAll()

  def testReleaseLock(self):
    """Test ReleaseLock()."""
    lock = 'foo'
    self.mox.StubOutWithMock(common, 'memcache')
    common.memcache.delete('lock_%s' % lock)
    self.mox.ReplayAll()
    common.ReleaseLock(lock)
    self.mox.VerifyAll()

  def testCreateManifestAsync(self):
    """Tests calling CreateManifest(delay=2)."""
    name = 'manifestname'
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(common.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-manifest-%s-%s' % (name, '2010-09-02-19-30-21')
    common.datetime.datetime.utcnow().AndReturn(utcnow)
    common.deferred.defer(
        common.CreateManifest, name, _name=deferred_name, _countdown=2)
    self.mox.ReplayAll()
    common.CreateManifest(name, delay=2)
    self.mox.VerifyAll()

  def testCreateManifestSuccess(self):
    """Tests the success path for CreateManifest()."""
    xml = 'fooxml'
    name = 'goodname'
    pkg1 = test.GenericContainer(install_types=['footype1'], name='pkg1')
    pkg2 = test.GenericContainer(
        install_types=['footype1', 'footype2'], name='pkg2')
    manifest_dict = {
        'catalogs': [name],
        pkg1.install_types[0]: [pkg1.name, pkg2.name],
        pkg2.install_types[1]: [pkg2.name],
    }
    self._MockObtainLock('manifest_lock_%s' % name)
    self.stubs.Set(
        common.plist_module,
        'MunkiManifestPlist',
        self.mox.CreateMock(common.plist_module.MunkiManifestPlist))

    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('manifests =', name).AndReturn([pkg1, pkg2])

    mock_plist = self.mox.CreateMockAnything()
    common.plist_module.MunkiManifestPlist().AndReturn(mock_plist)
    mock_plist.SetContents(manifest_dict)
    mock_plist.GetXml().AndReturn(xml)

    mock_manifest = self.MockModelStatic('Manifest', 'get_or_insert', name)
    mock_manifest.put().AndReturn(None)
    self.mox.StubOutWithMock(common.models.Manifest, 'ResetMemcacheWrap')
    common.models.Manifest.ResetMemcacheWrap(name).AndReturn(None)

    self._MockReleaseLock('manifest_lock_%s' % name)

    self.mox.ReplayAll()
    common.CreateManifest(name)
    self.assertEqual(mock_manifest.plist, xml)
    self.mox.VerifyAll()

  def testCreateManifestDbError(self):
    """Tests CreateManifest() with db Error."""
    name = 'goodname'
    self._MockObtainLock('manifest_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('manifests =', name).AndRaise(common.models.db.Error)

    self._MockReleaseLock('manifest_lock_%s' % name)

    self.mox.ReplayAll()
    self.assertRaises(common.models.db.Error, common.CreateManifest, name)
    self.mox.VerifyAll()

  def testCreateManifestWithNoPkgsinfo(self):
    """Tests CreateManifest() where no coorresponding PackageInfo exist."""
    name = 'badname'
    catalog = test.GenericContainer()
    self._MockObtainLock('manifest_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('manifests =', name).AndReturn([])
    self._MockReleaseLock('manifest_lock_%s' % name)

    self.mox.ReplayAll()
    self.assertRaises(
        common.ManifestCreationError, common.CreateManifest, name)
    self.mox.VerifyAll()

  def testCreateManifestLocked(self):
    """Tests CreateManifest() where name is locked."""
    name = 'lockedname'
    self._MockObtainLock('manifest_lock_%s' % name, obtain=False)
    # here is where CreateManifest calls itself; can't stub the method we're
    # testing, so mock the calls that happen as a result.
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(common.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-manifest-%s-%s' % (name, '2010-09-02-19-30-21')
    common.datetime.datetime.utcnow().AndReturn(utcnow)
    common.deferred.defer(
        common.CreateManifest, name, _name=deferred_name, _countdown=5)

    self.mox.ReplayAll()
    common.CreateManifest(name)
    self.mox.VerifyAll()

  def testCreateCatalogAsync(self):
    """Tests calling CreateCatalog(delay=2)."""
    name = 'catalogname'
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(common.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-catalog-%s-%s' % (name, '2010-09-02-19-30-21')
    common.datetime.datetime.utcnow().AndReturn(utcnow)
    common.deferred.defer(
        common.CreateCatalog, name, _name=deferred_name, _countdown=2)
    self.mox.ReplayAll()
    common.CreateCatalog(name, delay=2)
    self.mox.VerifyAll()

  def testCreateCatalogSuccess(self):
    """Tests the success path for CreateCatalog()."""
    name = 'goodname'
    catalog = self.mox.CreateMockAnything()
    plist1 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    pkg1 = test.GenericContainer(plist=plist1)
    plist2 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    pkg2 = test.GenericContainer(plist=plist2)
    self.mox.StubOutWithMock(common, 'CreateManifest')
    self._MockObtainLock('catalog_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('catalogs =', name).AndReturn([pkg1, pkg2])
    catalog = self.MockModelStatic('Catalog', 'get_or_insert', name)
    catalog.put().AndReturn(None)
    self.mox.StubOutWithMock(common.models.Catalog, 'ResetMemcacheWrap')
    common.models.Catalog.ResetMemcacheWrap(name).AndReturn(None)
    self._MockReleaseLock('catalog_lock_%s' % name)
    common.CreateManifest(name, delay=1).AndReturn(None)

    self.mox.ReplayAll()
    common.CreateCatalog(name)
    self.assertEqual(catalog.name, name)
    xml = ('<dict>\n    <key>foo</key>\n    <string>bar</string>\n  '
           '</dict>\n  <dict>\n    <key>foo</key>\n    '
           '<string>bar</string>\n  </dict>')
    plist = common.CATALOG_PLIST_XML % xml
    self.assertEqual(plist, catalog.plist)
    self.mox.VerifyAll()

  def testCreateCatalogWithNoPkgsinfo(self):
    """Tests CreateCatalog() where no coorresponding PackageInfo exist."""
    name = 'badname'
    catalog = test.GenericContainer()
    self._MockObtainLock('catalog_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('catalogs =', name).AndReturn([])
    self._MockReleaseLock('catalog_lock_%s' % name)

    self.mox.ReplayAll()
    self.assertRaises(
        common.CatalogCreationError, common.CreateCatalog, name)
    self.mox.VerifyAll()

  def testCreateCatalogWithPlistParseError(self):
    """Tests CreateCatalog() where plist.GetXmlDocument() raises plist.Error."""
    name = 'goodname'
    catalog = self.mox.CreateMockAnything()
    plist1 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    pkg1 = test.GenericContainer(plist=plist1)
    self._MockObtainLock('catalog_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('catalogs =', name).AndReturn([pkg1])
    self.mox.StubOutWithMock(
        common.plist_module, 'ApplePlist', self.mox.CreateMockAnything())
    mock_plist = self.mox.CreateMockAnything()
    common.plist_module.ApplePlist(pkg1.plist).AndReturn(mock_plist)
    mock_plist.Parse().AndRaise(common.plist_module.Error)
    self._MockReleaseLock('catalog_lock_%s' % name)

    self.mox.ReplayAll()
    self.assertRaises(
        common.plist_module.Error, common.CreateCatalog, name)
    self.mox.VerifyAll()

  def testCreateCatalogWithDbError(self):
    """Tests CreateCatalog() where put() raises db.Error."""
    name = 'goodname'
    catalog = self.mox.CreateMockAnything()
    plist1 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    pkg1 = test.GenericContainer(plist=plist1)
    plist2 = '<plist><dict><key>foo</key><string>bar</string></dict></plist>'
    pkg2 = test.GenericContainer(plist=plist2)
    self._MockObtainLock('catalog_lock_%s' % name)
    mock_model = self.MockModelStatic('PackageInfo', 'all')
    mock_model.filter('catalogs =', name).AndReturn([pkg1, pkg2])
    catalog = self.MockModelStatic('Catalog', 'get_or_insert', name)
    catalog.put().AndRaise(common.models.db.Error)
    self._MockReleaseLock('catalog_lock_%s' % name)

    self.mox.ReplayAll()
    self.assertRaises(
        common.models.db.Error, common.CreateCatalog, name)
    self.mox.VerifyAll()

  def testCreateCatalogLocked(self):
    """Tests CreateCatalog() where name is locked."""
    name = 'lockedname'
    self._MockObtainLock('catalog_lock_%s' % name, obtain=False)
    # here is where CreateCatalog calls itself; can't stub the method we're
    # testing, so mock the calls that happen as a result.
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(common.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'create-catalog-%s-%s' % (name, '2010-09-02-19-30-21')
    common.datetime.datetime.utcnow().AndReturn(utcnow)
    common.deferred.defer(
        common.CreateCatalog, name, _name=deferred_name, _countdown=5)

    self.mox.ReplayAll()
    common.CreateCatalog(name)
    self.mox.VerifyAll()

  def testLogClientConnectionWithInvalidUuid(self):
    """Tests LogClientConnection() function with an invalid uuid."""
    client_id = {'uuid': ''}
    event = 'custom'
    user_settings = {}

    self.mox.StubOutWithMock(common.logging, 'debug')
    common.logging.debug(
        'LogClientConnection(%s, %s, user_settings? %s, delay=%s)',
        event, client_id, user_settings not in [{}, None], 0)
    common.logging.debug(
        'uuid is unknown, skipping log.')

    self.mox.ReplayAll()
    common.LogClientConnection(event, client_id, user_settings)
    self.mox.VerifyAll()

  def testLogClientConnection(self):
    """Tests LogClientConnection() function."""
    user_settings = {'foo': 1}
    event = 'postflight'
    uuid = 'foo-uuid'
    hostname = 'foohostname'
    owner = 'foouser'
    track = 'footrack'
    config_track = 'footrack'
    site = 'NYC'
    office = 'US-NYC-FOO'
    os_version = '10.6.3'
    client_version = '0.6.0.759.0'
    on_corp = True
    last_notified_datetime_str = '2010-11-03 15:15:10'
    last_notified_datetime = datetime.datetime(2010, 11, 03, 15, 15, 10)
    uptime = 123
    root_disk_free = 456
    user_disk_free = 789
    client_id = {
        'uuid': uuid, 'hostname': hostname, 'owner': owner,
        'track': track, 'config_track': config_track, 'os_version': os_version,
        'client_version': client_version, 'on_corp': on_corp,
        'last_notified_datetime': last_notified_datetime_str,
        'site': site, 'office': office, 'uptime': uptime,
        'root_disk_free': root_disk_free, 'user_disk_free': user_disk_free,
    }
    connection_datetimes = range(1, common.CONNECTION_DATETIMES_LIMIT + 1)
    connection_dates = range(1, common.CONNECTION_DATES_LIMIT + 1)

    # bypass the db.run_in_transaction step
    self.stubs.Set(
      common.models.db, 'run_in_transaction',
      lambda fn, *args: fn(*args))

    mock_computer = self.MockModelStatic('Computer', 'get_by_key_name', uuid)
    mock_computer.connection_datetimes = connection_datetimes
    mock_computer.connection_dates = connection_dates
    mock_computer.connections_on_corp = None  # test (None or 0) + 1
    mock_computer.connections_off_corp = 0
    mock_computer.put().AndReturn(None)

    self.mox.ReplayAll()
    common.LogClientConnection(event, client_id, user_settings)
    self.assertEquals(uuid, mock_computer.uuid)
    self.assertEquals(hostname, mock_computer.hostname)
    self.assertEquals(owner, mock_computer.owner)
    self.assertEquals(track, mock_computer.track)
    self.assertEquals(config_track, mock_computer.config_track)
    self.assertEquals(site, mock_computer.site)
    self.assertEquals(office, mock_computer.office)
    self.assertEquals(os_version, mock_computer.os_version)
    self.assertEquals(client_version, mock_computer.client_version)
    self.assertEquals(
        last_notified_datetime, mock_computer.last_notified_datetime)
    # Verify that the first "datetime" was popped off.
    self.assertEquals(connection_datetimes[0], 2)
    # Verify that the last datetime is the new datetime.
    new_datetime = connection_datetimes[common.CONNECTION_DATETIMES_LIMIT - 1]
    self.assertEquals(type(new_datetime), datetime.datetime)
    # Verify that the first "date" was popped off.
    self.assertEquals(connection_dates[0], 2)
    # Verify that the last date is the new date.
    new_date = connection_dates[common.CONNECTION_DATES_LIMIT - 1]
    self.assertEquals(type(new_date), datetime.datetime)
    # Verify on_corp/off_corp counts.
    self.assertEquals(1, mock_computer.connections_on_corp)
    self.assertEquals(0, mock_computer.connections_off_corp)
    self.mox.VerifyAll()

  def testLogClientConnectionWhenNew(self):
    """Tests LogClientConnection() function."""
    user_settings = {'foo': 1}
    event = 'postflight'
    uuid = 'foo-uuid'
    hostname = 'foohostname'
    owner = 'foouser'
    track = 'footrack'
    config_track = 'footrack'
    site = 'NYC'
    office = 'US-NYC-FOO'
    os_version = '10.6.3'
    client_version = '0.6.0.759.0'
    on_corp = True
    last_notified_datetime_str = '2010-11-03 15:15:10'
    last_notified_datetime = datetime.datetime(
        2010, 11, 03, 15, 15, 10)
    uptime = 123
    root_disk_free = 456
    user_disk_free = 789
    client_id = {
        'uuid': uuid, 'hostname': hostname, 'owner': owner,
        'track': track, 'config_track': config_track, 'os_version': os_version,
        'client_version': client_version, 'on_corp': on_corp,
        'last_notified_datetime': last_notified_datetime_str,
        'site': site, 'office': office, 'uptime': uptime,
        'root_disk_free': root_disk_free, 'user_disk_free': user_disk_free,
    }

    # bypass the db.run_in_transaction step
    self.stubs.Set(
        common.models.db, 'run_in_transaction',
        lambda fn, *args: fn(*args))

    utc_now = common.datetime.datetime.utcnow()
    utc_now2 = datetime.datetime.combine(utc_now, datetime.time())
    self.stubs.Set(
        common.datetime,
        'datetime',
        self.mox.CreateMock(common.datetime.datetime))
    self.stubs.Set(
        common.datetime,
        'time',
        self.mox.CreateMock(common.datetime.time))
    common.datetime.datetime.utcnow().AndReturn(utc_now)
    common.datetime.datetime.strptime(
        last_notified_datetime_str, '%Y-%m-%d %H:%M:%S').AndReturn(
            last_notified_datetime)
    common.datetime.time().AndReturn('timeobj')
    common.datetime.datetime.combine(utc_now, 'timeobj').AndReturn(utc_now2)

    ne_mock_computer = self.MockModelStaticNone(
        'Computer', 'get_by_key_name', uuid)
    mock_computer = self.MockModel('Computer', key_name=uuid)
    self.mox.StubOutWithMock(common.deferred, 'defer')

    mock_computer.connection_datetimes = []
    mock_computer.connection_dates = []
    mock_computer.connections_on_corp = None
    mock_computer.connections_off_corp = None
    mock_computer.put().AndReturn(None)
    common.deferred.defer(
        common._SaveFirstConnection,
        client_id=client_id, computer=mock_computer, _countdown=300,
        _queue='first')

    self.mox.ReplayAll()
    common.LogClientConnection(event, client_id, user_settings)
    self.assertEquals(uuid, mock_computer.uuid)
    self.assertEquals(hostname, mock_computer.hostname)
    self.assertEquals(owner, mock_computer.owner)
    self.assertEquals(track, mock_computer.track)
    self.assertEquals(config_track, mock_computer.config_track)
    self.assertEquals(site, mock_computer.site)
    self.assertEquals(office, mock_computer.office)
    self.assertEquals(os_version, mock_computer.os_version)
    self.assertEquals(client_version, mock_computer.client_version)
    self.assertEquals(
        last_notified_datetime, mock_computer.last_notified_datetime)
    # Verify that the first "datetime" was popped off.
    self.assertEquals([utc_now], mock_computer.connection_datetimes)
    self.assertEquals([utc_now2], mock_computer.connection_dates)
    # Verify on_corp/off_corp counts.
    self.assertEquals(1, mock_computer.connections_on_corp)
    self.assertEquals(None, mock_computer.connections_off_corp)
    self.mox.VerifyAll()

  def testLogClientConnectionAsync(self):
    """Tests calling LogClientConnection(delay=2)."""
    user_settings = {}
    event = 'eventname'
    client_id = {'uuid': 'fooo'}
    utcnow = datetime.datetime(2010, 9, 2, 19, 30, 21, 377827)
    self.mox.StubOutWithMock(datetime, 'datetime')
    self.stubs.Set(common.deferred, 'defer', self.mox.CreateMockAnything())
    deferred_name = 'log-client-conn-%s-%s' % (
        client_id['uuid'], '2010-09-02-19-30-21')
    common.datetime.datetime.utcnow().AndReturn(utcnow)
    common.deferred.defer(
        common.LogClientConnection, event, client_id, user_settings,
        _name=deferred_name, _countdown=2)
    self.mox.ReplayAll()
    common.LogClientConnection(event, client_id, user_settings, delay=2)
    self.mox.VerifyAll()

  def _GetClientIdTestData(self):
    """Returns client id test data."""
    client_id_str = (
        'uuid=6c3327e9-6405-4f05-8374-142cbbd260c9|owner=foouser|'
        'hostname=foohost|config_track=fooconfigtrack|track=%s|'
        'os_version=10.6.3|client_version=0.6.0.759.0|on_corp=0|'
        'last_notified_datetime=2010-01-01|site=NYC|office=US-NYC-FOO|'
        'uptime=123.0|root_disk_free=456|user_disk_free=789'
    )
    client_id_dict = {
      'uuid': '6c3327e9-6405-4f05-8374-142cbbd260c9',
      'owner': 'foouser',
      'hostname': 'foohost',
      'config_track': 'fooconfigtrack',
      'site': 'NYC',
      'office': 'US-NYC-FOO',
      'os_version': '10.6.3',
      'client_version': '0.6.0.759.0',
      'on_corp': False,
      'last_notified_datetime': '2010-01-01',
      'uptime': 123.0,
      'root_disk_free': 456,
      'user_disk_free': 789,
    }
    return client_id_str, client_id_dict

  def testParseClientIdOnCorp(self):
    """Tests ParseClientId with on_corp=1."""
    client_id_str, client_id_dict = self._GetClientIdTestData()
    client_id_str = client_id_str.replace('on_corp=0', 'on_corp=1')
    client_id_dict['on_corp'] = True
    cid = client_id_str % 'stable'
    client_id_dict['track'] = 'stable'
    self.assertEqual(client_id_dict, common.ParseClientId(cid))

  def testParseClientIdWithValidClientIdAllValidTracks(self):
    """Tests ParseClientId() with a valid client id; tests all valid tracks."""
    client_id_str, client_id_dict = self._GetClientIdTestData()
    for track in common.common.TRACKS:
      cid = client_id_str % track
      client_id_dict['track'] = track
      self.assertEqual(client_id_dict, common.ParseClientId(cid))

  def testParseClientIdWithUuidOverride(self):
    """Tests ParseClientId() with uuid override."""
    uuid_override = 'foouuidbar'
    uuid_override_full = 'CN=%s' % uuid_override
    client_id_str, client_id_dict = self._GetClientIdTestData()
    client_id_dict['uuid'] = uuid_override
    for track in common.common.TRACKS:
      cid = client_id_str % track
      client_id_dict['track'] = track
      self.assertEqual(
          client_id_dict, common.ParseClientId(cid, uuid=uuid_override_full))

  def testParseClientIdWithInvalidType(self):
    """Tests ParseClientId() with an invalid type; checks for None."""
    client_id_str, client_id_dict = self._GetClientIdTestData()
    client_id_str = client_id_str.replace('uptime=123.0', 'uptime=hello')
    client_id_dict['uptime'] = None
    for track in common.common.TRACKS:
      cid = client_id_str % track
      client_id_dict['track'] = track
      self.assertEqual(client_id_dict, common.ParseClientId(cid))

  def testParseClientIdWithoutRequiredFields(self):
    """Tests ParseClientId() without required fields"""
    client_id_dict = {}
    for key in common.CLIENT_ID_FIELDS.keys():
      client_id_dict[key] = None
    client_id_dict['track'] = common.common.DEFAULT_TRACK
    # empty cid
    self.assertEqual(client_id_dict, common.ParseClientId(''))
    # empty cid with delimiters
    self.assertEqual(client_id_dict, common.ParseClientId('|||'))
    # cid with unknown key name
    client_id_dict['ASDFMOOCOW'] = '1'
    self.assertEqual(client_id_dict, common.ParseClientId('ASDFMOOCOW=1'))
    del(client_id_dict['ASDFMOOCOW'])

  def testIsPanicMode(self):
    """Tests IsPanicMode()."""
    mode = common.PANIC_MODES[0]
    k = '%s%s' % (common.PANIC_MODE_PREFIX, mode)

    self.mox.StubOutWithMock(
        common.models.KeyValueCache, 'MemcacheWrappedGet')

    common.models.KeyValueCache.MemcacheWrappedGet(k).AndReturn(1)
    common.models.KeyValueCache.MemcacheWrappedGet(k).AndReturn(None)

    self.mox.ReplayAll()
    self.assertTrue(common.IsPanicMode(mode))
    self.assertFalse(common.IsPanicMode(mode))
    self.assertRaises(ValueError, common.IsPanicMode, 'never a mode')
    self.mox.VerifyAll()

  def testSetPanicModeWhenValueError(self):
    self.mox.ReplayAll()
    self.assertRaises(ValueError, common.SetPanicMode, 'never a mode', True)
    self.mox.VerifyAll()

  def testSetPanicModeWhenEnable(self):
    """Tests SetPanicMode()."""
    mode = common.PANIC_MODES[0]
    k = '%s%s' % (common.PANIC_MODE_PREFIX, mode)

    self.mox.StubOutWithMock(
        common.models.KeyValueCache, 'get_by_key_name')
    self.mox.StubOutWithMock(
        common.models.KeyValueCache, 'ResetMemcacheWrap')
    self.mox.StubOutWithMock(
        common.models, 'KeyValueCache')
    mock_entity = self.mox.CreateMockAnything()

    common.models.KeyValueCache.get_by_key_name(k).AndReturn('existing')
    common.models.KeyValueCache.ResetMemcacheWrap(k).AndReturn(None)

    common.models.KeyValueCache.get_by_key_name(k).AndReturn(None)
    common.models.KeyValueCache(key_name=k).AndReturn(mock_entity)
    mock_entity.put().AndReturn(None)
    common.models.KeyValueCache.ResetMemcacheWrap(k).AndReturn(None)

    self.mox.ReplayAll()
    common.SetPanicMode(mode, True)
    common.SetPanicMode(mode, True)
    self.assertEqual(mock_entity.text_value, '1')
    self.mox.VerifyAll()

  def testSetPanicModeWhenDisable(self):
    """Tests SetPanicMode()."""
    mode = common.PANIC_MODES[0]
    k = '%s%s' % (common.PANIC_MODE_PREFIX, mode)

    self.mox.StubOutWithMock(
        common.models.KeyValueCache, 'get_by_key_name')
    self.mox.StubOutWithMock(
        common.models.KeyValueCache, 'ResetMemcacheWrap')
    self.mox.StubOutWithMock(
        common.models, 'KeyValueCache')
    mock_entity = self.mox.CreateMockAnything()

    common.models.KeyValueCache.get_by_key_name(k).AndReturn(mock_entity)
    mock_entity.delete()
    common.models.KeyValueCache.ResetMemcacheWrap(k).AndReturn(None)

    common.models.KeyValueCache.get_by_key_name(k).AndReturn(None)
    common.models.KeyValueCache.ResetMemcacheWrap(k).AndReturn(None)

    self.mox.ReplayAll()
    common.SetPanicMode(mode, False)
    common.SetPanicMode(mode, False)
    self.mox.VerifyAll()

  def testIsPanicModeNoPackages(self):
    """Test IsPanicModeNoPackages()."""
    self.mox.StubOutWithMock(common, 'IsPanicMode')
    common.IsPanicMode(common.PANIC_MODE_NO_PACKAGES).AndReturn(123)
    self.mox.ReplayAll()
    self.assertEqual(123, common.IsPanicModeNoPackages())
    self.mox.VerifyAll()

  def testSetPanicModeNoPackages(self):
    """Test SetPanicModeNoPackages()."""
    enabled = 12345
    self.mox.StubOutWithMock(common, 'SetPanicMode')
    common.SetPanicMode(common.PANIC_MODE_NO_PACKAGES, enabled).AndReturn(0)
    self.mox.ReplayAll()
    common.SetPanicModeNoPackages(enabled)
    self.mox.VerifyAll()

  def testWriteMSULog(self):
    """Test WriteComputerMSULog()."""
    uuid = 'uuid'
    details = {
        'event': 'event',
        'source': 'source',
        'user': 'user',
        'time': 1292013344.12,
        'desc': 'desc',
    }
    key = '%s_%s_%s' % (uuid, details['source'], details['event'])
    mock_model = self.MockModelStatic('ComputerMSULog', 'get_or_insert', key)
    mock_model.mtime = None
    mock_model.put().AndReturn(None)

    self.mox.ReplayAll()
    common.WriteComputerMSULog(uuid, details)
    self.assertEqual(mock_model.uuid, uuid)
    self.assertEqual(mock_model.event, details['event'])
    self.assertEqual(mock_model.source, details['source'])
    self.assertEqual(mock_model.user, details['user'])
    self.assertEqual(mock_model.desc, details['desc'])
    self.assertEqual(
        mock_model.mtime.strftime('%Y%m%d%H%M%S'), '20101210203544')
    self.mox.VerifyAll()

  def testWriteMSULogWhenOlder(self):
    """Test WriteComputerMSULog()."""
    uuid = 'uuid'
    details = {
        'event': 'event',
        'source': 'source',
        'user': 'user',
        'time': 1292013344.12,
        'desc': 'desc',
    }
    key = '%s_%s_%s' % (uuid, details['source'], details['event'])
    mock_model = self.MockModelStatic('ComputerMSULog', 'get_or_insert', key)
    mock_model.mtime = common.datetime.datetime(2011, 1, 1, 0, 0, 0)

    self.mox.ReplayAll()
    common.WriteComputerMSULog(uuid, details)
    self.mox.VerifyAll()


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()