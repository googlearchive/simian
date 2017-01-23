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
"""Reports URL handlers."""

import datetime
import json
import logging
import os
import re
import urllib

from simian.auth import gaeserver
from simian.mac import common as main_common
from simian.mac import models
from simian.mac.common import gae_util
from simian.mac.common import util
from simian.mac.munki import common
from simian.mac.munki import handlers


# int number of days after which postflight_datetime is considered stale.
FORCE_CONTINUE_POSTFLIGHT_DAYS = 5

# int number of failed Munki executions before instructing the client to repair.
REPAIR_CLIENT_PREFLIGHT_COUNT_SINCE_POSTFLIGHT = 5

INSTALL_RESULT_FAILED = 'FAILED with return code'
INSTALL_RESULT_SUCCESSFUL = 'SUCCESSFUL'

JSON_PREFIX = ')]}\',\n'

LEGACY_INSTALL_RESULTS_STRING_REGEX = re.compile(
    r'^Install of (.*)-(\d+.*): (%s|%s: (\-?\d+))$' % (
        INSTALL_RESULT_SUCCESSFUL, INSTALL_RESULT_FAILED))

# Example: 'iLife 11: Download failed (Error -1001: The request timed out.)'
DOWNLOAD_FAILED_STRING_REGEX = re.compile(
    r'([\s\w\.\-]+): Download failed \((.*)\)')

# For legacy clients that do not support multiple feedback commands via JSON,
# this list is used to determine which single command to send, if any, in
# increasing importance order.
LEGACY_FEEDBACK_LIST = ['EXIT', 'FORCE_CONTINUE', 'REPAIR', 'UPLOAD_LOGS']


def IsExitFeedbackIpAddress(ip_address):
  """Is this an IP address that should result in an exit feedback?

  Args:
    ip_address: str, like "1.2.3.4"
  Returns:
    True if this IP address should result in exit feedback
  """
  return (
      ip_address and
      models.KeyValueCache.IpInList('client_exit_ip_blocks', ip_address))


class Reports(handlers.AuthenticationHandler):
  """Handler for /reports/."""

  def GetReportFeedback(self, uuid, report_type, **kwargs):
    """Inspect a report and provide a feedback status/command.

    Args:
      uuid: str, computer uuid
      report_type: str, report type
      **kwargs: dict, additional report parameters, e.g:
          on_corp: str, optional, '1' or '0', on_corp status
          message: str, optional, message from client
          details: str, optional, details from client
          ip_address: str, optional, IP address of client
    Returns:
      common.ReportFeedback.* constant
    """
    feedback = {}
    if 'computer' in kwargs:
      c = kwargs['computer']
    else:
      c = models.Computer.get_by_key_name(uuid)
    ip_address = kwargs.get('ip_address', None)
    client_exit = kwargs.get('client_exit', None)

    if client_exit and report_type == 'preflight':
      # client has requested an exit, but let's ensure we should allow it.
      if c is None or c.postflight_datetime is None:
        # client has never fully executed Munki.
        feedback['force_continue'] = True
      else:
        # check if the postflight_datetime warrants a FORCE_CONTINUE
        now = datetime.datetime.utcnow()
        postflight_stale_datetime = now - datetime.timedelta(
            days=FORCE_CONTINUE_POSTFLIGHT_DAYS)
        if c.postflight_datetime < postflight_stale_datetime:
          # client hasn't executed Munki in FORCE_CONTINUE_POSTFLIGHT_DAYS.
          feedback['force_continue'] = True
        else:
          feedback['exit'] = True
    elif report_type == 'preflight':
      if IsExitFeedbackIpAddress(ip_address):
        feedback['exit'] = True
      elif common.IsPanicModeNoPackages():
        feedback['exit'] = True
      elif not c or c.preflight_datetime is None:
        # this is the first preflight post from this client.
        feedback['force_continue'] = True
      elif getattr(c, 'upload_logs_and_notify', None) is not None:
        feedback['logging_level'] = 3
        feedback['upload_logs'] = True
      else:
        # check if preflight_count_since_postflight warrants a repair.
        if (c.preflight_count_since_postflight >=
            REPAIR_CLIENT_PREFLIGHT_COUNT_SINCE_POSTFLIGHT):
          feedback['pkill_installd'] = True
          feedback['pkill_softwareupdated'] = True
          feedback['repair'] = True
          feedback['logging_level'] = 3
          feedback['upload_logs'] = True


    return feedback

  def _LogInstalls(self, installs, computer):
    """Logs a batch of installs for a given computer.

    Args:
      installs: list, of str install data from a preflight/postflight report.
      computer: models.Computer entity.
    """
    if not installs:
      return

    on_corp = self.request.get('on_corp')
    if on_corp == '1':
      on_corp = True
    elif on_corp == '0':
      on_corp = False
    else:
      on_corp = None

    to_put = []
    for install in installs:
      if install.startswith('Install of'):
        d = {
            'applesus': 'false',
            'duration_seconds': None,
            'download_kbytes_per_sec': None,
            'name': install,
            'status': 'UNKNOWN',
            'version': '',
            'unattended': 'false',
        }
        # support for old 'Install of FooPkg-1.0: SUCCESSFUL' style strings.
        try:
          m = LEGACY_INSTALL_RESULTS_STRING_REGEX.search(install)
          if not m:
            raise ValueError
          elif m.group(3) == INSTALL_RESULT_SUCCESSFUL:
            d['status'] = 0
          else:
            d['status'] = m.group(4)
          d['name'] = m.group(1)
          d['version'] = m.group(2)
        except (IndexError, AttributeError, ValueError):
          logging.warning('Unknown install string format: %s', install)
      else:
        # support for new 'name=pkg|version=foo|...' style strings.
        d = common.KeyValueStringToDict(install)

      name = d.get('display_name', '') or d.get('name', '')
      version = d.get('version', '')
      status = str(d.get('status', ''))
      applesus = common.GetBoolValueFromString(d.get('applesus', '0'))
      unattended = common.GetBoolValueFromString(d.get('unattended', '0'))
      try:
        duration_seconds = int(d.get('duration_seconds', None))
      except (TypeError, ValueError):
        duration_seconds = None
      try:
        dl_kbytes_per_sec = int(d.get('download_kbytes_per_sec', None))
        # Ignore zero KB/s download speeds, as that's how Munki reports
        # unknown speed.
        if dl_kbytes_per_sec == 0:
          dl_kbytes_per_sec = None
      except (TypeError, ValueError):
        dl_kbytes_per_sec = None

      try:
        install_datetime = util.Datetime.utcfromtimestamp(d.get('time', None))
      except ValueError as e:
        logging.info('Ignoring invalid install_datetime: %s', str(e))
        install_datetime = datetime.datetime.utcnow()
      except util.EpochExtremeFutureValueError as e:
        logging.info('Ignoring extreme future install_datetime: %s', str(e))
        install_datetime = datetime.datetime.utcnow()
      except util.EpochFutureValueError:
        install_datetime = datetime.datetime.utcnow()

      pkg = '%s-%s' % (name, version)
      entity = models.InstallLog(
          uuid=computer.uuid, computer=computer, package=pkg, status=status,
          on_corp=on_corp, applesus=applesus, unattended=unattended,
          duration_seconds=duration_seconds, mtime=install_datetime,
          dl_kbytes_per_sec=dl_kbytes_per_sec)
      entity.success = entity.IsSuccess()
      to_put.append(entity)

    gae_util.BatchDatastoreOp(models.db.put, to_put)

  def post(self):
    """Reports get handler.

    Returns:
      A webapp.Response() response.
    """
    session = gaeserver.DoMunkiAuth()
    uuid = main_common.SanitizeUUID(session.uuid)
    report_type = self.request.get('_report_type')
    report_feedback = {}
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
      apple_updates_to_install = self.request.get_all(
          'apple_updates_to_install')

      computer = models.Computer.get_by_key_name(uuid)
      ip_address = os.environ.get('REMOTE_ADDR', '')
      if report_type == 'preflight':
        # we want to get feedback now, before preflight_datetime changes.
        client_exit = self.request.get('client_exit', None)
        report_feedback = self.GetReportFeedback(
            uuid, report_type, computer=computer, ip_address=ip_address,
            client_exit=client_exit)

        if self.request.get('json') == '1':
          self.response.out.write(JSON_PREFIX + json.dumps(report_feedback))
        else:
          # For legacy clients that accept a single string, not JSON.
          feedback_to_send = 'OK'
          for feedback in LEGACY_FEEDBACK_LIST:
            if report_feedback.get(feedback.lower()):
              feedback_to_send = feedback
          self.response.out.write(feedback_to_send)

        # if report feedback calls for a client exit, log it.
        if report_feedback.get('exit'):
          if not client_exit:
            # client didn't ask for an exit, which means server decided.
            client_exit = 'Connection from defined exit IP address'
          common.WriteClientLog(
              models.PreflightExitLog, uuid, computer=computer,
              exit_reason=client_exit)

      cert_fingerprint = None

      common.LogClientConnection(
          report_type, client_id, user_settings, pkgs_to_install,
          apple_updates_to_install, computer=computer, ip_address=ip_address,
          report_feedback=report_feedback, cert_fingerprint=cert_fingerprint)


    elif report_type == 'install_report':
      computer = models.Computer.get_by_key_name(uuid)

      self._LogInstalls(self.request.get_all('installs'), computer)

      for removal in self.request.get_all('removals'):
        common.WriteClientLog(
            models.ClientLog, uuid, computer=computer, action='removal',
            details=removal)

      for problem in self.request.get_all('problem_installs'):
        common.WriteClientLog(
            models.ClientLog, uuid, computer=computer,
            action='install_problem', details=problem)
    elif report_type == 'broken_client':
      # Default reason of "objc" to support legacy clients, existing when objc
      # was the only broken state ever reported.
      reason = self.request.get('reason', 'objc')
      details = self.request.get('details')
      logging.warning('Broken Munki client (%s): %s', reason, details)
      common.WriteBrokenClient(uuid, reason, details)
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
