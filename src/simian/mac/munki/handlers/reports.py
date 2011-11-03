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
import os
import re
import time
import urllib
from google.appengine.ext import webapp
from simian.auth import gaeserver
from simian.mac import models
from simian.mac import common as main_common
from simian.mac.munki import common
from simian.mac.munki import handlers
from simian.mac.common import util

# int number of days after which postflight_datetime is considered stale.
FORCE_CONTINUE_POSTFLIGHT_DAYS = 5

# int number of days after which a client is considered broken.
REPAIR_CLIENT_PRE_POST_DIFF_DAYS = 7

# InstallResults legacy string matching regex.
LEGACY_INSTALL_RESULTS_STRING_REGEX = (
    '^Install of (.*)-(\d+.*): (SUCCESSFUL|FAILED with return code: (\-?\d+))$')


class ReportFeedback(object):
  """Class container for feedback status constants."""

  # Client should proceed as normally defined.
  OK = 'OK'

  # Client should NOT exit and instead continue, even if this means masking
  # an error which it would usually stop running because of.
  FORCE_CONTINUE = 'FORCE_CONTINUE'

  # Client should exit instead of continuing as normal.
  EXIT = 'EXIT'

  # Client should repair (download and reinstall) itself.
  REPAIR = 'REPAIR'

  # Client should send logs to the server.
  UPLOAD_LOGS = 'UPLOAD_LOGS'


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
    if 'computer' in kwargs:
      c = kwargs['computer']
    else:
      c = models.Computer.get_by_key_name(uuid)

    # TODO(user): if common.BusinessLogicMethod ...
    if report_type == 'preflight':
      if not c or c.preflight_datetime is None:
        # this is the first preflight post from this host
        report = ReportFeedback.FORCE_CONTINUE
      elif getattr(c, 'upload_logs_and_notify', None) is not None:
        report = ReportFeedback.UPLOAD_LOGS
      elif c.postflight_datetime is None:
        # client has posted preflight before, but not postflight
        report = ReportFeedback.REPAIR
      else:
        # check if postflight_datetime warrants a repair.
        pre_post_timedelta = c.preflight_datetime - c.postflight_datetime
        if pre_post_timedelta > datetime.timedelta(
            days=REPAIR_CLIENT_PRE_POST_DIFF_DAYS):
          report = ReportFeedback.REPAIR
    elif report_type == 'preflight_exit':
      if c is None or c.postflight_datetime is None:
        # host has never fully executed Munki.
        report = ReportFeedback.FORCE_CONTINUE
      else:
        # check if the postflight_datetime warrants a FORCE_CONTINUE
        now = datetime.datetime.utcnow()
        postflight_stale_datetime = now - datetime.timedelta(
            days=FORCE_CONTINUE_POSTFLIGHT_DAYS)
        if c.postflight_datetime < postflight_stale_datetime:
          # host hasn't fully executed Munki in FORCE_CONTINUE_POSTFLIGHT_DAYS.
          report = ReportFeedback.FORCE_CONTINUE

    if report not in [ReportFeedback.OK, ReportFeedback.FORCE_CONTINUE]:
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
      try:
        if user_settings_str:
          user_settings = util.Deserialize(
              urllib.unquote(str(user_settings_str)))
      except util.DeserializeError:
        logging.warning(
            'Client %s sent broken user_settings: %s',
            client_id_str, user_settings_str)
      pkgs_to_install = self.request.get_all('pkgs_to_install')
      computer = models.Computer.get_by_key_name(uuid)
      ip_address = os.environ.get('REMOTE_ADDR', '')
      if report_type == 'preflight':
        # if the UUID is known to be lost/stolen, log this connection.
        if models.ComputerLostStolen.IsLostStolen(uuid):
          logging.warning('Connection from lost/stolen machine: %s', uuid)
          models.ComputerLostStolen.LogLostStolenConnection(
              computer=computer, ip_address=ip_address)
        # we want to get feedback now, before preflight_datetime changes.
        if feedback:
          self.response.out.write(
              self.GetReportFeedback(uuid, report_type, computer=computer))
      common.LogClientConnection(
          report_type, client_id, user_settings, pkgs_to_install,
          computer=computer, ip_address=ip_address)
    elif report_type == 'install_report':
      on_corp = self.request.get('on_corp')
      if on_corp == '1':
        on_corp = True
      elif on_corp == '0':
        on_corp = False
      else:
        on_corp = None
      for install in self.request.get_all('installs'):
        if install.startswith('Install of'):
          # support for old 'Install of FooPkg-1.0: SUCCESSFUL' style strings.
          try:
            m = re.search(LEGACY_INSTALL_RESULTS_STRING_REGEX, install)
            if m.group(3) == 'SUCCESSFUL':
              status = 0
            else:
              status = m.group(4)
            d = {
                'name': m.group(1), 'version': m.group(2), 'applesus': 'false',
                'status': status, 'duration_seconds': None,
            }
          except (IndexError, AttributeError):
            logging.warning('Unknown install string format: %s', install)
            d = {
                'name': install, 'version': '', 'applesus': 'false',
                'status': 'UNKNOWN', 'duration_seconds': None,
            }
        else:
          # support for new 'name=pkg|version=foo|...' style strings.
          d = common.KeyValueStringToDict(install)

        name = d.get('name', '')
        version = d.get('version', '')
        status = str(d.get('status', ''))
        applesus = common.GetBoolValueFromString(d.get('applesus', '0'))
        try:
          duration_seconds = int(d.get('duration_seconds', None))
        except (TypeError, ValueError):
          duration_seconds = None
        try:
          install_datetime = util.Datetime.utcfromtimestamp(d.get('time', None))
        except ValueError, e:
          logging.warning('Ignoring invalid install_datetime; %s' % str(e))
          install_datetime = None
        except util.EpochExtremeFutureValueError, e:
          logging.warning('Ignoring future install_datetime; %s' % str(e))
          install_datetime = None
        except util.EpochValueError, e:
          install_datetime = None
        pkg = '%s-%s' % (name, version)
        common.WriteClientLog(
            models.InstallLog, uuid, package=pkg, status=status,
            on_corp=on_corp, applesus=applesus,
            duration_seconds=duration_seconds, mtime=install_datetime)
      for removal in self.request.get_all('removals'):
        common.WriteClientLog(
            models.ClientLog, uuid, action='removal', details=removal)
      for problem in self.request.get_all('problem_installs'):
        common.WriteClientLog(
            models.ClientLog, uuid, action='install_problem', details=problem)
    elif report_type == 'preflight_exit':
      message = self.request.get('message')
      computer = common.WriteClientLog(
          models.PreflightExitLog, uuid, exit_reason=message)
    elif report_type == 'broken_client':
      details = self.request.get('details')
      logging.warning('Broken Munki client: %s', details)
      common.WriteBrokenClient(uuid, details)
    elif report_type == 'msu_log':
      details = {}
      for k in ['time', 'user', 'source', 'event', 'desc']:
        details[k] = self.request.get(k, None)
      common.WriteComputerMSULog(uuid, details)
    else:
      # unknown report type; log all post params.
      params = []
      for param in self.request.arguments():
        params.append('%s=%s' % (param, self.request.get_all(param)))
      common.WriteClientLog(
          models.ClientLog, uuid, action='unknown', details=str(params))

    # If the client asked for feedback, get feedback and respond.
    # Skip this if the report_type is preflight, as report feedback was
    # retrieved before LogComputerConnection changed preflight_datetime.
    if feedback and report_type != 'preflight':
      self.response.out.write(
          self.GetReportFeedback(
              uuid, report_type,
              message=message, details=details, computer=computer,
          ))