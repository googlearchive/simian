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

"""Reports URL handlers."""



import datetime
import logging
import re
import urllib
from google.appengine.ext import webapp
from simian.auth import gaeserver
from simian.mac import models
from simian.mac import common as main_common
from simian.mac.munki import common
from simian.mac.munki import handlers
from simian.mac.common import util

# int number of days after which postflight_datetime is considered stale.
POSTFLIGHT_STALE_DAYS = 7


class ReportFeedback(object):
  """Class container for feedback status constants."""

  # Client should proceed as normally defined.
  OK = 'OK'

  # Client should NOT exit and instead continue, even if this means masking
  # an error which it would usually stop running because of.
  FORCE_CONTINUE = 'FORCE_CONTINUE'

  # Client should exit instead of continuing as normal.
  EXIT = 'EXIT'


class Reports(handlers.AuthenticationHandler, webapp.RequestHandler):
  """Handler for /reports/."""

  def GetReportFeedback(self, uuid, report_type, **kwargs):
    """Inspect a report and provide a feedback status/command.

    Args:
      uuid: str, computer uuid
      report_type: str, report type
      kwargs: dict, additional report parameters, e.g:

      on_corp: str, optional, '1' or '0', on_corp status
      message: str, optional, message from client
      details: str, optional, details from client
    Returns:
      ReportFeedback.* constant
    """
    report = ReportFeedback.OK

    # TODO(user): if common.BusinessLogicMethod ...
    if report_type == 'preflight_exit':
      if 'computer' in kwargs:
        c = kwargs['computer']
      else:
        c = models.Computer.get_by_key_name(uuid)


      if c is None or c.postflight_datetime is None:
        # host has never fully executed Simian.
        report = ReportFeedback.FORCE_CONTINUE
      else:
        now = datetime.datetime.utcnow()
        postflight_stale_datetime = now - datetime.timedelta(
            days=POSTFLIGHT_STALE_DAYS)
        if c.postflight_datetime < postflight_stale_datetime:
          # host hasn't fully executed Simian in POSTFLIGHT_STALE_DAYS days.
          report = ReportFeedback.FORCE_CONTINUE

    if report != ReportFeedback.OK:
      logging.warning('Feedback to %s: %s', uuid, report)

    return report

  def post(self):
    """Reports get handler.

    Returns:
      A webapp.Response() response.
    """
    session = gaeserver.DoMunkiAuth()
    uuid = main_common.SanitizeUUID(session.uuid)
    report_type = self.request.get('_report_type')
    feedback = self.request.get('_feedback')
    message = None
    details = None
    client_id = None
    computer = None

    if report_type == 'preflight' or report_type == 'postflight':
      client_id_str = urllib.unquote(self.request.get('client_id'))
      client_id = common.ParseClientId(client_id_str, uuid=uuid)
      user_settings_str = self.request.get('user_settings')
      user_settings = None
      pkgs_to_install = self.request.get_all('pkgs_to_install')
      common.LogClientConnection(
          report_type, client_id, user_settings, pkgs_to_install)
    elif report_type == 'install_report':
      on_corp = self.request.get('on_corp')
      if on_corp == '1':
        on_corp = True
      elif on_corp == '0':
        on_corp = False
      else:
        on_corp = None
      for install in self.request.get_all('installs'):
        logging.debug('Install: %s', install)
        try:
          install, status = install.split(':', 1)
        except ValueError:
          status = 'UNKNOWN'
        else:
          install = install[len('Install of '):]
          status = status.strip()
        logging.debug(
            'Package: %s, Status: %s, On Corp: %s', install, status, on_corp)
        common.WriteClientLog(
            models.InstallLog, uuid, package=install, status=status,
            on_corp=on_corp)
      for removal in self.request.get_all('removals'):
        logging.debug('Removal: %s', removal)
        common.WriteClientLog(
            models.ClientLog, uuid, action='removal', details=removal)
      for problem in self.request.get_all('problem_installs'):
        logging.info('Install problem: %s', problem)
        common.WriteClientLog(
            models.ClientLog, uuid, action='install_problem', details=problem)
    elif report_type == 'preflight_exit':
      message = self.request.get('message')
      logging.debug('Munki execution failure; preflight exit: %s', message)
      computer = common.WriteClientLog(
          models.PreflightExitLog, uuid, exit_reason=message)
    elif report_type == 'broken_client':
      details = self.request.get('details')
      logging.warning('Broken Munki client: %s', details)
      common.WriteBrokenClient(details)
    elif report_type == 'msu_log':
      details = {}
      for k in ['time', 'user', 'source', 'event', 'desc']:
        details[k] = self.request.get(k, None)
      try:
        details['time'] = int(float(details['time']))
      except ValueError:
        logging.warning('Invalid value for msu_log time: %s', details['time'])
        details['time'] = None
      common.WriteComputerMSULog(uuid, details)
    else:
      # unknown report type; log all post params.
      params = []
      for param in self.request.arguments():
        params.append('%s=%s' % (param, self.request.get_all(param)))
      logging.debug('Unknown /reports POST: %s', params)
      common.WriteClientLog(
          models.ClientLog, uuid, action='unknown', details=str(params))

    if feedback:
      self.response.out.write(
          self.GetReportFeedback(
              uuid, report_type,
              message=message, details=details, computer=computer,
          ))