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



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from simian.mac.common import test
from simian.mac.munki.handlers import reports


class HandlersTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return reports.Reports()

  def GetTestClassModule(self):
    return reports

  def testGetReportFeedbackWithPassedComputer(self):
    """Tests GetReportFeedback() with a passed Computer object."""
    report_type = 'preflight_exit'
    track = 'unstable'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.postflight_datetime = reports.datetime.datetime.utcnow()
    self.assertEqual(
        reports.ReportFeedback.OK,
        self.c.GetReportFeedback('uuid', report_type, computer=computer))

  def testGetReportFeedbackWithoutPassedComputer(self):
    """Tests GetReportFeedback() without a passed Computer object."""
    report_type = 'preflight_exit'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.postflight_datetime = reports.datetime.datetime.utcnow()
    self.mox.StubOutWithMock(reports.models.Computer, 'get_by_key_name')
    reports.models.Computer.get_by_key_name(uuid).AndReturn(computer)
    self.mox.ReplayAll()
    self.assertEqual(
        reports.ReportFeedback.OK,
        self.c.GetReportFeedback(uuid, report_type))
    self.mox.VerifyAll()

  def testGetReportFeedbackWithNonePostflightDatetime(self):
    """Tests GetReportFeedback() with a Computer.postflight_datetime=None."""
    report_type = 'preflight_exit'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    computer.postflight_datetime = None
    self.mox.ReplayAll()
    self.assertEqual(
        reports.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackWithStalePostflightDatetime(self):
    """Tests GetReportFeedback() with a stale Computer.postflight_datetime."""
    report_type = 'preflight_exit'
    track = 'unstable'
    uuid = 'foouuid'
    computer = self.mox.CreateMockAnything()
    computer.track = track
    stale_days = reports.POSTFLIGHT_STALE_DAYS + 1  # 1 day stale.
    computer.postflight_datetime = (reports.datetime.datetime.utcnow() -
        reports.datetime.timedelta(days=stale_days))
    self.mox.ReplayAll()
    self.assertEqual(
        reports.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=computer))
    self.mox.VerifyAll()

  def testGetReportFeedbackWithNoneComputer(self):
    """Tests GetReportFeedback() with a passed Computer object."""
    report_type = 'preflight_exit'
    uuid = 'foouuid'
    self.mox.ReplayAll()
    self.assertEqual(
        reports.ReportFeedback.FORCE_CONTINUE,
        self.c.GetReportFeedback(uuid, report_type, computer=None))
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
    uuid = 'foouuid'
    client_id_str = 'clientidstring'
    client_id_dict = {'nothing': True}
    feedback = 'foofeedback'
    pkgs_to_install = ['FooApp1', 'FooApp2']
    user_settings = None
    user_settings_data = None

    self.PostSetup(uuid=uuid, report_type=report_type, feedback=feedback)
    self.request.get('client_id').AndReturn(client_id_str)
    self.mox.StubOutWithMock(reports.common, 'ParseClientId')
    reports.common.ParseClientId(client_id_str, uuid=uuid).AndReturn(
        client_id_dict)
    self.request.get('user_settings').AndReturn(user_settings_data)
    self.request.get_all('pkgs_to_install').AndReturn(pkgs_to_install)
    self.mox.StubOutWithMock(reports.common, 'LogClientConnection')
    reports.common.LogClientConnection(
        report_type, client_id_dict, user_settings, pkgs_to_install)
    self.mox.StubOutWithMock(self.c, 'GetReportFeedback')
    self.c.GetReportFeedback(
        uuid, report_type, message=None, details=None, computer=None).AndReturn(
            'yes')
    self.response.out.write('yes')

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testPostPreflight(self):
    """Tests post() with _report_type=preflight."""
    self.PostPreflightOrPostflight(report_type='preflight')

  def testPostPostflight(self):
    """Tests post() with _report_type=postflight."""
    self.PostPreflightOrPostflight(report_type='postflight')

  def PostInstallReportInstalls(self, on_corp=True):
    """Tests post() with _report_type=install_report."""
    uuid = 'foouuid'
    report_type = 'install_report'
    installs = [
        'Install of FooApp1: SUCCESSFUL',
        'Install of FooApp2: FAILED with return code: 1',
        'NOT A VALID INSTALL STRING',
    ]
    self.PostSetup(uuid=uuid, report_type=report_type)
    if on_corp:
      self.request.get('on_corp').AndReturn('1')
    else:
      self.request.get('on_corp').AndReturn('0')
    self.request.get_all('installs').AndReturn(installs)
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='FooApp1', status='SUCCESSFUL',
        on_corp=on_corp)
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='FooApp2',
        status='FAILED with return code: 1', on_corp=on_corp)
    reports.common.WriteClientLog(
        reports.models.InstallLog, uuid, package='NOT A VALID INSTALL STRING',
        status='UNKNOWN', on_corp=on_corp)

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

  def testPostPreflightExist(self):
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
    reports.common.WriteBrokenClient(details)

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
    details['time'] = 12345  # time value is cast to float() then int()

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