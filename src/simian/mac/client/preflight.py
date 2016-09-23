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
"""Custom preflight script to run before bulk of Munki executions.

Exit codes: see constants below.
"""

import datetime
import errno
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import urllib

from munkilib import munkicommon

from simian.mac.client import client as mac_client
from simian.mac.client import flight_common
from simian.mac.client import network_detect


# Start exit codes
STATUS_SUCCESS = (0, 'SUCCESS')
STATUS_FAIL_AUTH = (10, 'failure obtaining auth token')
STATUS_FAIL_CONFIG_SETUP = (13, 'Config setup errors')
STATUS_SERVER_EXIT_FEEDBACK = (14, 'Server send EXIT command')
# End exit codes
LAST_RUN_FILE = '/Library/Managed Installs/lastrun'
MAX_ATTEMPTS = 4
MSULOGFILE = '/Users/Shared/.com.googlecode.munki.ManagedSoftwareUpdate.log'
MSULOGDIR = '/Users/Shared/.com.googlecode.munki.ManagedSoftwareUpdate.logs'

# Prefix to prevent Cross Site Script Inclusion.
JSON_PREFIX = ')]}\',\n'

DEBUG = False
if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)
else:
  logging.getLogger().setLevel(logging.INFO)


def WriteRootCaCerts(client):
  """Write the internal root CA certs to a file."""
  logging.debug('WriteRootCaCerts')
  managed_installs_dir = munkicommon.pref('ManagedInstallDir')
  certs_dir = os.path.join(managed_installs_dir, 'certs')
  cert_file_path = os.path.join(certs_dir, 'ca.pem')
  if not os.path.isdir(certs_dir):
    os.makedirs(certs_dir)

  tmpfile = tempfile.NamedTemporaryFile(
      dir=os.path.dirname(os.path.realpath(cert_file_path)))
  tmpfile.write(client.GetSystemRootCACertChain())

  logging.debug('WriteRootCaCerts: writing to tmp %s', tmpfile.name)

  try:
    os.unlink(cert_file_path)
  except OSError:
    pass

  try:
    os.link(tmpfile.name, cert_file_path)
  except OSError as e:
    tmpfile.close()
    raise client.Error('Error writing root CA certs: %s' % str(e))

  tmpfile.close()
  logging.debug('WriteRootCaCerts: success')


def LoginToServer(secure_config, client_id, user_settings, client_exit=None):
  """Sets an auth token cookie header to a plist object.

  Args:
    secure_config: secure Preferences object.
    client_id: dict client identifier.
    user_settings: dict of user settings.
    client_exit: optional, default None, str explaining why the client is
      requesting to exit its execution.
  Returns:
    Tuple of a SimianAuthClient, a dict containing feedback from the server.
  """
  headers = []

  # Preserve all non-Cookie and non-ClientID headers that may exist.
  if munkicommon.ADDITIONAL_HTTP_HEADERS_KEY in secure_config:
    for header in secure_config[munkicommon.ADDITIONAL_HTTP_HEADERS_KEY]:
      if (not header.startswith('Cookie:') and
          not header.startswith(flight_common.MUNKI_CLIENT_ID_HEADER_KEY) and
          not header.startswith('User-Agent:')):
        headers.append(header)

  client_id_str = flight_common.DictToStr(client_id)

  if user_settings:
    try:
      user_settings_str = urllib.quote(
          json.dumps(flight_common.Flatten(user_settings)))
    except TypeError:
      logging.error(
          'preflight cannot flatten user_settings: %s', str(user_settings))
      user_settings_str = ''
  else:
    user_settings_str = ''

  client_params = {
      '_report_type': 'preflight',
      'client_id': client_id_str,
      'user_settings': user_settings_str,
      'json': '1',
  }
  if client_exit:
    client_params['client_exit'] = client_exit

  client_params = urllib.urlencode(client_params)

  url = flight_common.GetServerURL()
  client = mac_client.SimianAuthClient(hostname=url)
  token = client.GetAuthToken()
  response = client.PostReportBody(client_params)
  feedback = {}
  try:
    feedback = json.loads(response[len(JSON_PREFIX):])
  except ValueError:
    logging.exception('Error parsing JSON')

  if not isinstance(feedback, dict):
    logging.error(
        'preflight failure getting feedback dict (%r)', feedback)

  # Add the Cookie and client id to the headers.
  headers.append('User-Agent: gzip')  # enforce GFE compression
  headers.append('Cookie: %s' % token)
  headers.append('%s: %s' % (
      flight_common.MUNKI_CLIENT_ID_HEADER_KEY, client_id_str))
  # Replace AdditionalHttpHeaders with the new headers list.
  secure_config[munkicommon.ADDITIONAL_HTTP_HEADERS_KEY] = headers

  return client, feedback


def CreateEmptyDirectory(attempt=0):
  """Create and/or maintain an empty directory.

  Args:
    attempt: int, default 0, the attempt number.
  Returns:
    str, path to empty directory
  Exits:
    with status STATUS_FAIL_CONFIG_SETUP[0] if MAX_ATTEMPTS have been made.
  """
  if attempt == MAX_ATTEMPTS:
    logging.error('preflight failure setting up empty dir')
    sys.exit(STATUS_FAIL_CONFIG_SETUP[0])

  time.sleep(attempt)

  managed_installs_dir = munkicommon.pref('ManagedInstallDir')
  path = os.path.join(managed_installs_dir, '.purposefully_empty_dir')

  remove = False
  create = False

  if os.path.exists(path):
    if os.path.isdir(path):
      if os.listdir(path):
        remove = 'd'
    else:
      remove = 'f'
  else:
    create = True

  if remove:
    try:
      if remove == 'd':
        shutil.rmtree(path)
      elif remove == 'f':
        os.unlink(path)
    except OSError as e:
      if e.args[0] == errno.ENOENT:
        # it went missing after we just found it.  try to regain control.
        logging.critical('%s went missing after it existed', path)
        return CreateEmptyDirectory(attempt + 1)
      else:
        # some other error.
        return CreateEmptyDirectory(attempt + 1)

  if remove or create:
    try:
      os.mkdir(path)
    except OSError as e:
      if e.args[0] == errno.EEXIST:
        # it already exists.  try to regain control of it.
        return CreateEmptyDirectory(attempt + 1)
      else:
        # some other error.  try again.
        logging.critical('mkdir(%s) error: %s', path, str(e))
        return CreateEmptyDirectory(attempt + 1)

  return path


def GetManagedSoftwareUpdateLogFile(logfile=MSULOGFILE):
  """Get logs from one MSU log file.

  This function modifies the existing log file by removing it, thus
  rolling the logs also.

  Args:
    logfile: str, log file to open
  Returns:
    array of dicts in form = {
      'time': float, Unix timestamp
      'user': str, like "username"
      'source': str, like "MSU",
      'event': str, like "launched"
      'desc': str, like "additional descriptive text"
    }
  """
  if not os.path.exists(logfile):
    return []

  name = '%s.%d.%d' % (logfile, os.getpid(), time.time())
  try:
    os.link(logfile, name)
  except OSError:
    return []

  fd = open(name, 'r')
  os.unlink(logfile)
  logs = []

  try:
    log_re = re.compile(r'^(\d+\.\d+) INFO (\w+) : @@([^:]+):([^:]+)@@\s?(.*)')

    r = fd.readline()
    while r:
      r = r.strip()
      m = log_re.search(r)
      if m:
        logs.append({
            'time': float(m.group(1)),
            'user': m.group(2),
            'source': m.group(3),
            'event': m.group(4),
            'desc': m.group(5),
        })
      r = fd.readline()

    fd.close()
  except IOError as e:
    # some error parsing the logs, logs may have been lost now.
    # returning the symlink is possible to put the log file back, but
    # problematic if new log files were written during processing.
    # just continue with what we have and mark failure.
    logs.append({
        'time': time.time(),
        'user': 'preflight',
        'source': 'truncate',
        'event': 'truncate',
        'desc': str(e)})

  try:
    os.unlink(name)
  except OSError:
    pass

  return logs


def GetManagedSoftwareUpdateLogs():
  """Get logs from all MSU log files.

  Returns:
    array of dicts in same form as GetManagedSoftwareUpdateLogFile().
  """
  logs = []
  logs.extend(GetManagedSoftwareUpdateLogFile(MSULOGFILE))
  if os.path.isdir(MSULOGDIR):
    for name in os.listdir(MSULOGDIR):
      logs.extend(
          GetManagedSoftwareUpdateLogFile(os.path.join(MSULOGDIR, name)))
  return logs


def PostManagedSoftwareUpdateLogs(client, logs):
  """Post Managed Software Update logs to Munki server.

  Args:
    client:  A SimianAuthClient object.
    logs: same format as output from GetManagedSoftwareUpdateLogs.
  """
  for log in logs:
    # TODO(user):  Combine all of these into a single HTTP request.
    client.PostReport('msu_log', log)


def NoteLastRun(open_=open):
  """Writes to file to indicate last run."""
  output_file = open_(LAST_RUN_FILE, 'w')
  output_file.write('Run')




def RunPreflight(runtype, server_url=None):
  """Run the full Preflight script."""

  NoteLastRun()
  # support enterprise/802.1x user-context wifi auth.
  # don't bother to perform preflight and exit OK immediately since there's no
  # network connection.
  if runtype == 'logoutinstall':
    sys.exit(0)

  # load the NONSECURE ManagedInstalls.plist
  regular_config = munkicommon.ManagedInstallsPreferences()

  if server_url:
    regular_config['SoftwareRepoURL'] = server_url

  secure_config = munkicommon.SecureManagedInstallsPreferences()

  # update the ClientIdentifier key with the custom client id.
  client_id = flight_common.GetClientIdentifier(runtype)
  secure_config['ClientIdentifier'] = client_id['track']

  # load user settings
  try:
    user_settings = flight_common.GetUserSettings()
  except ValueError as e:
    logging.warning('User settings are malformed: %s', str(e))
    user_settings = {'__malformed': True}

  # If the munki exec is an auto run (launchd), exit if on WWAN or Android WAP.
  client_exit = None
  if runtype == 'auto':
    if network_detect.IsOnWwan():
      client_exit = 'WWAN device ppp0 is active'
    elif network_detect.IsOnAndroidWap():
      client_exit = 'Android WAP tether is active'
    elif network_detect.IsOnIosWap():
      client_exit = 'iOS WAP tether is active'
    elif network_detect.IsOnMifi():
      client_exit = 'MiFi tether is active'
    elif network_detect.IsOnBackoffWLAN():
      client_exit = 'Backoff WLAN SSID detected'

  # get a client auth token/cookie from the server, and post connection data.
  client, feedback = LoginToServer(
      secure_config, client_id, user_settings, client_exit)

  WriteRootCaCerts(client)

  if feedback.get('upload_logs'):
    # write new token/client_id headers to secure plist and upload logs.
    flight_common.UploadClientLogFiles(client)

  if feedback.get('pkill_installd'):
    # terminate any pending installations, like misbehaving Apple updates.
    flight_common.Pkill(process='installd', waitfor=2)

  if feedback.get('pkill_softwareupdated'):
    # terminate potentially hung softareupdated processes.
    flight_common.Pkill(process='softwareupdated', waitfor=2)

  if feedback.get('repair'):
    # write new token/client_id headers to secure plist and repair client.
    try:
      logging.info('Reinstalling Munki client....')
      flight_common.RepairClient()
      logging.info('Client successfully reinstalled.')
    except flight_common.RepairClientError as e:
      logging.exception(u'RepairClientError: %s', e)

  if feedback.get('logging_level'):
    regular_config['LoggingLevel'] = feedback.get('logging_level')
  else:
    regular_config['LoggingLevel'] = 1  # default to 1 if not set by server.

  if feedback.get('exit'):
    logging.warning('preflight received EXIT feedback from server; exiting....')
    sys.exit(STATUS_SERVER_EXIT_FEEDBACK[0])

  # post recent MSU logs
  logs = GetManagedSoftwareUpdateLogs()
  PostManagedSoftwareUpdateLogs(client, logs)

  # load user settings
  if user_settings:
    regular_config['UserSettings'] = user_settings
  else:
    if 'UserSettings' in regular_config:
      del regular_config['UserSettings']  # wipe existing UserSettings.

  # setup blank directory for capath setting
  path = CreateEmptyDirectory()
  regular_config['SoftwareRepoCAPath'] = path

  # enable MSU logging
  regular_config['MSULogEnabled'] = True


  # If setting is enabled, force Simian Apple SUS integration.
  if client_id.get('applesus'):
    regular_config['InstallAppleSoftwareUpdates'] = True
    # Get Apple Software Update Service catalog from server and set locally.
    flight_common.UpdateAppleSUSCatalog(client)

  # Report installs/etc to server.
  flight_common.UploadAllManagedInstallReports(
      client, client_id.get('on_corp', 'None'))

  # Delete the temp dir that munkicommon creates on import.
  munkicommon.cleanUpTmpDir()

  logging.debug('Preflight completed successfully.')
