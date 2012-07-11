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

"""Munki reports module tests."""




import datetime
import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import reports


class HandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return reports.Reports()

  def GetTestClassModule(self):
    return reports

  def _MockIsPanicModeNoPackages(self, panic_mode=False):
    """Utility method to mock common.IsPanicModeNoPackages().

    Args:
      panic_mode: bool, optional, True if panic mode should be returned
    """
    self.mox.StubOutWithMock(reports.common, 'IsPanicModeNoPackages')
    reports.common.IsPanicModeNoPackages().AndReturn(panic_mode)

  def _MockIsExitFeedbackIpAddress(self, ip_address=None, match=False):
    """Utility method to mock IsExitFeedbackIpAddress() calls.

    Args:
      ip_address: str, optional, IP like '1.2.3.4'
      match: bool, optional, True if the ip_address matches the exit list
    """
    self.mox.StubOutWithMock(reports, 'IsExitFeedbackIpAddress')
    reports.IsExitFeedbackIpAddress(ip_address).AndReturn(match)

  def testIsExitFeedbackIpAddress(self):
    """Tests _IsExitFeedbackIpAddress()."""
    self.mox.StubOutWithMock(reports.models.KeyValueCache, 'IpInList')

    ip_address = '1.2.3.4'
    reports.models.KeyValueCache.IpInList(
        'client_exit_ip_blocks', ip_address).AndReturn(True)

    self.mox.ReplayAll()
    self.assertFalse(reports.IsExitFeedbackIpAddress(None))
    self.assertTrue(reports.IsExitFeedbackIpAddress(ip_address))
    self.mox.VerifyAll()

  def testGetReportFeedbackWithPassedComputer(self):
    """Tests GetReportFeedback() with a passed Computer object."""
    report_type = 'preflight_exit'
    track = 'unstable'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.upload_logs_and_notify = None
    computer.postflight_datetime = reports.datetime.datetime.utcnow()
    self.assertEqual(
        reports.common.ReportFeedback.OK,
        self.c.GetReportFeedback('uuid', report_type, computer=computer))

  def testGetReportFeedbackWithoutPassedComputer(self):
    """Tests GetReportFeedback() without a passed Computer object."""
    report_type = 'preflight_exit'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.upload_logs_and_notify = None
    computer.postflight_datetime = reports.datetime.datetime.utcnow()
    self.mox.StubOutWithMock(reports.models.Computer, 'get_by_key_name')
    reports.models.Computer.get_by_key_name(uuid).AndReturn(computer)
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.OK,
        self.c.GetReportFeedback(uuid, report_type))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightExitWithExit(self):
    """Tests GetReportFeedback() with a successful client exit."""
    report_type = 'preflight'
    client_exit = 'WWAN active'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.postflight_datetime = reports.datetime.datetime.utcnow()
    computer.upload_logs_and_notify = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.EXIT,
        self.c.GetReportFeedback(uuid, report_type, computer=computer,
            client_exit=client_exit))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightExitWithNonePostflightDatetime(self):
    """Tests GetReportFeedback() with a Computer.postflight_datetime=None."""
    report_type = 'preflight'
    client_exit = 'WWAN active'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.postflight_datetime = None
    computer.upload_logs_and_notify = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=computer,
            client_exit=client_exit))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightExitWithStalePostflightDatetime(self):
    """Tests GetReportFeedback() with a stale Computer.postflight_datetime."""
    report_type = 'preflight'
    client_exit = 'WWAN active'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.upload_logs_and_notify = None
    stale_days = reports.FORCE_CONTINUE_POSTFLIGHT_DAYS + 1  # 1 day stale.
    computer.postflight_datetime = (reports.datetime.datetime.utcnow() -
        reports.datetime.timedelta(days=stale_days))
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=computer,
            client_exit=client_exit))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightExitWithNoneComputer(self):
    """Tests GetReportFeedback() with a passed Computer object."""
    report_type = 'preflight'
    client_exit = 'WWAN active'
    uuid = 'foouuid'
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=None,
            client_exit=client_exit))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightWithOKPostflightDatetime(self):
    """Tests GetReportFeedback(preflight) with OK postflight datetime."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    dt = datetime.datetime.utcnow() - datetime.timedelta(days=14)
    computer = self.mox.CreateMockAnything()
    computer.preflight_datetime = dt
    computer.postflight_datetime = dt
    computer.upload_logs_and_notify = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.OK,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightWithNoneComputer(self):
    """Tests GetReportFeedback(preflight) with computer=None."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=None))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightWithNoPreflightDatetime(self):
    """Tests GetReportFeedback(preflight) where preflight_datetime=None."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    computer = self.mox.CreateMockAnything()
    computer.preflight_datetime = None
    computer.upload_logs_and_notify = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightWithNoPostflightDatetime(self):
    """Tests GetReportFeedback(preflight) where postflight_dateime=None."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    computer = self.mox.CreateMockAnything()
    computer.postflight_datetime = None
    computer.upload_logs_and_notify = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.REPAIR,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackPreflightWithOldPostflightDatetime(self):
    """Tests GetReportFeedback(preflight) where postflight_datetime is old."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    dt = datetime.datetime.utcnow() - datetime.timedelta(days=3)
    computer = self.mox.CreateMockAnything()
    computer.upload_logs_and_notify = None
    computer.preflight_datetime = dt
    computer.postflight_datetime = dt - datetime.timedelta(days=10)
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.REPAIR,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackUploadLogs(self):
    """Tests GetReportFeedback(preflight) where upload_logs == True."""
    report_type = 'preflight'
    uuid = 'foouuid'
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages()
    computer = self.mox.CreateMockAnything()
    computer.preflight_datetime = True
    computer.upload_logs_and_notify = 'user@example.com'
    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.UPLOAD_LOGS,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackWhenIsExitFeedbackIpAddress(self):
    """Tests GetReportFeedback(preflight) when the IsExitFeedbackIpAddress."""
    report_type = 'preflight'
    uuid = 'foouuid'
    ip_address = '1.2.3.4'
    computer = self.mox.CreateMockAnything()
    self._MockIsExitFeedbackIpAddress(ip_address=ip_address, match=True)

    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.EXIT,
        self.c.GetReportFeedback(
            uuid, report_type, computer=computer, ip_address=ip_address))
    self.mox.VerifyAll()

  def testGetReportFeedbackWhenIsPanicModeNoPackages(self):
    """Tests GetReportFeedback(preflight) when IsPanicModeNoPackages."""
    report_type = 'preflight'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    self._MockIsExitFeedbackIpAddress()
    self._MockIsPanicModeNoPackages(True)

    self.mox.ReplayAll()
    self.assertEqual(
        reports.common.ReportFeedback.EXIT,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def PostSetup(self, uuid=None, report_type=None, feedback=None):
    """Sets up standard mocks and their actions for reports post()."""
    if uuid:
      session = self.mox.CreateMockAnything()
      session.uuid = uuid
      self.MockDoMunkiAuth(and_return=session)
    else:
      self.MockDoMunkiAuth(and_return=session)
    self.request.get('_report_type').AndReturn(report_type)
    self.request.get('_feedback').AndReturn(feedback)
    self.mox.StubOutWithMock(reports.common, 'WriteClientLog')

  def PostPreflightOrPostflight(self, report_type=None):
    """Tests post() with _report_type=preflight or postflight."""
    self.mox.StubOutWithMock(self.c, 'GetReportFeedback')
    uuid = 'foouuid'
    client_id_str = 'clientidstring'
    client_id_dict = {'nothing': True}
    feedback = 'foofeedback'
    pkgs_to_install = ['FooApp1', 'FooApp2']
    apple_updates_to_install = ['FooUpdate1', 'FooUpdate2']
    ip_address = 'fooip'
    client_exit = None
    reports.os.environ['REMOTE_ADDR'] = ip_address
    user_settings = None
    user_settings_data = None

    mock_computer = self.MockModelStatic('Computer', 'get_by_key_name', uuid)
    report_feedback = None
    if report_type == 'preflight':
      report_feedback = 'preflight_only'
      self.mox.StubOutWithMock(
          reports.models.ComputerLostStolen, 'IsLostStolen')
      reports.models.ComputerLostStolen.IsLostStolen(uuid).AndReturn(False)
      self.c.GetReportFeedback(
          uuid, report_type, computer=mock_computer,
          ip_address=ip_address, client_exit=client_exit).AndReturn(
              report_feedback)
      self.response.out.write(report_feedback)

    self.PostSetup(uuid=uuid, report_type=report_type, feedback=feedback)
    self.request.get('client_id').AndReturn(client_id_str)
    self.mox.StubOutWithMock(reports.common, 'ParseClientId')
    reports.common.ParseClientId(client_id_str, uuid=uuid).AndReturn(
        client_id_dict)
    self.request.get('user_settings').AndReturn(user_settings_data)
    self.request.get_all('pkgs_to_install').AndReturn(pkgs_to_install)
    self.request.get_all('apple_updates_to_install').AndReturn(
        apple_updates_to_install)

    if report_type == 'preflight':
      self.request.get('client_exit', None).AndReturn(None)

    self.mox.StubOutWithMock(reports.common, 'LogClientConnection')
    reports.common.LogClientConnection(
        report_type, client_id_dict, user_settings, pkgs_to_install,
        apple_updates_to_install, computer=mock_computer, ip_address=ip_address,
        report_feedback=report_feedback)


    if report_type != 'preflight':
      self.c.GetReportFeedback(
          uuid, report_type, message=None, details=None,
          computer=mock_computer).AndReturn('end_report')
      self.response.out.write('end_report')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostPreflight(self):
    """Tests post() with _report_type=preflight."""
    self.PostPreflightOrPostflight(report_type='preflight')

  def testPostPostflight(self):
    """Tests post() with _report_type=postflight."""
    self.PostPreflightOrPostflight(report_type='postflight')

  def PostInstallReportInstallsOld(self, on_corp=True):
    """Tests post() with _report_type=install_report with old style strings."""
    uuid = 'foouuid'
    report_type = 'install_report'
    installs = [
        'Install of Foo App1-1.0.0: SUCCESSFUL',
        'Install of Foo App2-123123: SUCCESSFUL',
        'Install of Foo App3-2.1.1: FAILED with return code: 1',
        'Install of Foo App4-456456: FAILED with return code: -5',
        'Install of broken string, so m.group(#) raises AttributeError',
    ]
    self.PostSetup(uuid=uuid, report_type=report_type)
    if on_corp:
      self.request.get('on_corp').AndReturn('1')
    else:
      self.request.get('on_corp').AndReturn('0')
    self.request.get_all('installs').AndReturn(installs)

    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='Foo App1-1.0.0',
        status='0', on_corp=on_corp, applesus=False, duration_seconds=None,
        dl_kbytes_per_sec=None, mtime=None)

    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='Foo App2-123123',
        status='0', on_corp=on_corp, applesus=False, duration_seconds=None,
        dl_kbytes_per_sec=None, mtime=None)

    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='Foo App3-2.1.1',
        status='1', on_corp=on_corp, applesus=False, duration_seconds=None,
        dl_kbytes_per_sec=None, mtime=None)

    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='Foo App4-456456',
        status='-5', on_corp=on_corp, applesus=False, duration_seconds=None,
        dl_kbytes_per_sec=None, mtime=None)

    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package=installs[-1] + '-',
        status='UNKNOWN', on_corp=on_corp, applesus=False,
        duration_seconds=None, dl_kbytes_per_sec=None, mtime=None)

    self.request.get_all('removals').AndReturn([])
    self.request.get_all('problem_installs').AndReturn([])

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostInstallReportInstallsOnCorpOld(self):
    """Tests post() with _report_type=install_report on_corp=1."""
    self.PostInstallReportInstallsOld(on_corp=True)

  def testPostInstallReportInstallsOffCorpOld(self):
    """Tests post() with _report_type=install_report on_corp=0."""
    self.PostInstallReportInstallsOld(on_corp=False)

  def PostInstallReportInstalls(self, on_corp=True):
    """Tests post() with _report_type=install_report with old style strings."""
    uuid = 'foouuid'
    report_type = 'install_report'
    installs = [
        ('name=FooApp1|version=1.0.0|applesus=0|status=0|duration_seconds=100'
         '|download_kbytes_per_sec=225'),

        ('name=FooApp2|version=2.1.1|applesus=0|status=2|duration_seconds=200'
         '|time=1312818179.1415989|download_kbytes_per_sec=1024'),

        ('name=FutureApp|version=9.9.9|applesus=false|status=0'
         '|duration_seconds=60|time=9999999999.1415989'
         '|download_kbytes_per_sec=0'),

        ('name=iTunes|version=10.2.0|applesus=1|status=0|duration_seconds=300'
         '|time=asdf'),

         'name=Safari|version=5.1.0|applesus=true|status=0|duration_seconds=4',
    ]
    self.PostSetup(uuid=uuid, report_type=report_type)
    if on_corp:
      self.request.get('on_corp').AndReturn('1')
    else:
      self.request.get('on_corp').AndReturn('0')
    self.request.get_all('installs').AndReturn(installs)
    # successful munki install report, lacking time.
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='FooApp1-1.0.0',
        status='0', on_corp=on_corp, applesus=False, duration_seconds=100,
        mtime=None, dl_kbytes_per_sec=225)
    # failed munki install report, with time.
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='FooApp2-2.1.1',
        status='2', on_corp=on_corp, applesus=False, duration_seconds=200,
        mtime=datetime.datetime(2011, 8, 8, 15, 42, 59), dl_kbytes_per_sec=1024)
    # successful munki install report, with future time.
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='FutureApp-9.9.9',
        status='0', on_corp=on_corp, applesus=False, duration_seconds=60,
        mtime=None, dl_kbytes_per_sec=None)
    # successful applesus install report with bogus time.
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='iTunes-10.2.0',
        status='0', on_corp=on_corp, applesus=True, duration_seconds=300,
        mtime=None, dl_kbytes_per_sec=None)
    # successful applesus install report with no time.
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='Safari-5.1.0',
        status='0', on_corp=on_corp, applesus=True, duration_seconds=4,
        mtime=None, dl_kbytes_per_sec=None)

    self.request.get_all('removals').AndReturn([])
    self.request.get_all('problem_installs').AndReturn([])

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostInstallReportInstallsOnCorp(self):
    """Tests post() with _report_type=install_report on_corp=1."""
    self.PostInstallReportInstalls(on_corp=True)

  def testPostInstallReportInstallsOffCorp(self):
    """Tests post() with _report_type=install_report on_corp=0."""
    self.PostInstallReportInstalls(on_corp=False)

  def testPostInstallReportRemovals(self):
    """Tests post() with _report_type=install_report."""
    uuid = 'foouuid'
    report_type = 'install_report'
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.request.get('on_corp').AndReturn('1')
    self.request.get_all('installs').AndReturn([])
    self.request.get_all('removals').AndReturn(['removal1', 'removal2'])

    reports.common.WriteClientLog(
        reports.models.ClientLog, uuid, action='removal', details='removal1')
    reports.common.WriteClientLog(
        reports.models.ClientLog, uuid, action='removal', details='removal2')
    self.request.get_all('problem_installs').AndReturn([])

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostInstallReportProblems(self):
    """Tests post() with _report_type=install_report."""
    uuid = 'foouuid'
    report_type = 'install_report'
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.request.get('on_corp').AndReturn('1')
    self.request.get_all('installs').AndReturn([])
    self.request.get_all('removals').AndReturn([])

    self.request.get_all('problem_installs').AndReturn(['problem1', 'problem2'])
    reports.common.WriteClientLog(
        reports.models.ClientLog, uuid, action='install_problem',
        details='problem1')
    reports.common.WriteClientLog(
        reports.models.ClientLog, uuid, action='install_problem',
        details='problem2')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostPreflightExit(self):
    """Tests post() with _report_type=preflight_exit."""
    uuid = 'foouuid'
    report_type = 'preflight_exit'
    message = 'foomessage'
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.request.get('message').AndReturn(message)
    reports.common.WriteClientLog(
        reports.models.PreflightExitLog, uuid, exit_reason=message)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostBrokenClient(self):
    """Tests post() with _report_type=broken_client."""
    uuid = 'foouuid'
    report_type = 'broken_client'
    details = 'foodetails'
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.request.get('details').AndReturn(details)
    self.mox.StubOutWithMock(reports.common, 'WriteBrokenClient')
    reports.common.WriteBrokenClient(uuid, details)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostMsuLog(self):
    """Tests post() with _report_type = msu_log."""
    uuid = 'fooooooo'
    report_type = 'msu_log'
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.mox.StubOutWithMock(reports.common, 'WriteComputerMSULog')
    details = {}

    for k in ['time', 'user', 'source', 'event', 'desc']:
      if k == 'time':
        details[k] = '12345.34'
      else:
        details[k] = k
      self.request.get(k, None).AndReturn(details[k])

    reports.common.WriteComputerMSULog(uuid, details).AndReturn(None)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostUnknownReportType(self):
    """Tests post() with an unknown _report_type."""
    uuid = 'foouuid'
    report_type = 'This is not a valid report type --- not a chance!'
    arguments = {1: 'yes', 2: 'no', 3: 'maybe'}
    self.PostSetup(uuid=uuid, report_type=report_type)
    self.request.arguments().AndReturn(arguments)
    params = []
    for arg in arguments:
      self.request.get_all(arg).AndReturn(arguments[arg])
      params.append('%s=%s' % (arg, arguments[arg]))
    reports.common.WriteClientLog(
        reports.models.ClientLog, uuid, action='unknown',
        details="['1=yes', '2=no', '3=maybe']")

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()



def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()