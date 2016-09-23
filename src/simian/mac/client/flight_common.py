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
"""Custom preflight/postflight common module."""

import ctypes
import ctypes.util
import datetime
import errno
import fcntl
import logging
import os
import platform
import plistlib  # cannot read binary plists, be careful!
import re
import select
import signal
import struct
import subprocess
import tempfile
import time

from simian.mac.client import version

# Place all ObjC-dependent imports in this try/except block.
# Silently work around missing modules within this module using OBJC_OK!
# pylint: disable=g-import-not-at-top,import-error,relative-import
try:
  from munkilib import FoundationPlist as fpl
  from munkilib import munkicommon
  from munkilib import updatecheck
  from munkilib import fetch
  import SystemConfiguration as sys_config
  import Foundation
  import objc
  OBJC_OK = True
except ImportError:
  # Python does not have ObjC bindings.
  OBJC_OK = False


FACTER_CMD = '/usr/local/bin/simianfacter'
DATETIME_STR_FORMAT = '%Y-%m-%d %H:%M:%S'
DELIMITER = '|'
APPLE_SUS_PLIST = '/Library/Preferences/com.apple.SoftwareUpdate.plist'
APPLE_SUS_CATALOG = '/Library/Managed Installs/applesus.sucatalog'
DEFAULT_SECURE_MANAGED_INSTALLS_PLIST_PATH = (
    '/private/var/root/Library/Preferences/ManagedInstalls.plist')
DEFAULT_MANAGED_INSTALLS_PLIST_PATH = (
    '/Library/Preferences/ManagedInstalls.plist')
DEFAULT_ADDITIONAL_HTTP_HEADERS_KEY = 'AdditionalHttpHeaders'
# Global for holding the auth token to be used to communicate with the server.
AUTH1_TOKEN = None
HUNG_MSU_TIMEOUT = datetime.timedelta(hours=2)
MUNKI_CLIENT_ID_HEADER_KEY = 'X-munki-client-id'


DEBUG = False
if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)
else:
  logging.getLogger().setLevel(logging.INFO)


class Error(Exception):
  """Class for domain specific exceptions."""


class ServerRequestError(Error):
  """Error issuing request to server."""


class RepairClientError(Error):
  """Error repairing client."""


def GetClientVersion():
  """Returns the str Munki + Simian version."""
  if not OBJC_OK:
    return ''
  return '%s %s' % (munkicommon.get_version(), version.VERSION)


def GetServerURL():
  """Returns the server URL str from ManagedInstalls or const var URL."""
  url = GetPlistValue('SoftwareRepoURL', secure=False)
  return url


def _GetConsoleUser():
  """Returns the logged in console username, or None if nobody is logged in."""
  logging.warning('facter primary_user empty; fetching from sys_config')
  if OBJC_OK:
    # this returns a tuple of (username, uid, gid)
    # if no console user is logged in, it'll be (None, 0, 0)
    return sys_config.SCDynamicStoreCopyConsoleUser(None, None, None)[0] or ''
  else:
    return None


def _GetHostname():
  """Returns the hostname from SystemConfiguration."""
  logging.warning('facter hostname empty; fetching from sys_config')
  if OBJC_OK:
    # this returns a tuple of (computer name, useless int)
    return sys_config.SCDynamicStoreCopyComputerName(None, None)[0]
  else:
    return None


def _GetSerialNumber():
  """Returns the str serial number from system_profiler, or '' if not found."""
  return_code, stdout, unused_stderr = Exec(
      'system_profiler SPHardwareDataType')
  if return_code == 0 and stdout:
    match = re.search(r'^\s+Serial Number[^:]+: (.*)$', stdout, re.MULTILINE)
    if match:
      return match.group(1)
  return ''


def _GetHardwareUUID():
  """Returns the str hardware UUID from system_profiler, or '' if not found."""
  return_code, stdout, unused_stderr = Exec(
      'system_profiler SPHardwareDataType')
  if return_code == 0 and stdout:
    match = re.search(r'^\s+Hardware UUID: (.*)$', stdout, re.MULTILINE)
    if match:
      return match.group(1)
  return ''


def _GetPrimaryUser():
  """Returns the str username of the user that has logged in the most."""
  return_code, stdout, unused_stderr = Exec(['/usr/bin/last', '-100'])
  if return_code == 0 and stdout:
    users = {}
    for line in stdout.splitlines():
      user = line.split(' ')[0]
      users[user] = users.get(user, 0) + 1
    users_list = users.keys()
    users_list.sort(cmp=lambda x, y: cmp(users[x], users[y]), reverse=True)
    return users_list[0]
  return ''


def _GetMachineInfoPlistValue(key):
  """Returns value of given key in the machineinfo plist, or '' if not found."""
  return ''


def SetFileNonBlocking(f, non_blocking=True):
  """Set non-blocking flag on a file object.

  Args:
    f: file
    non_blocking: bool, default True, non-blocking mode or not
  """
  flags = fcntl.fcntl(f.fileno(), fcntl.F_GETFL)
  if bool(flags & os.O_NONBLOCK) != non_blocking:
    flags ^= os.O_NONBLOCK
  fcntl.fcntl(f.fileno(), fcntl.F_SETFL, flags)


def Exec(cmd, env=None, timeout=0, waitfor=0):
  """Executes a process and returns exit code, stdout, stderr.

  Args:
    cmd: str or sequence, command and optional arguments to execute.
    env: dict, optional, environment variables to set.
    timeout: int or float, if >0, Exec() will stop waiting for output
      after timeout seconds and kill the process it started.  return code
      might be undefined, or -SIGTERM, use waitfor to make sure to obtain it.
      values <1 will be crudely rounded off because of select() sleep time.
    waitfor: int or float, if >0, Exec() will wait waitfor seconds
      before asking for the process exit status one more time.
  Returns:
    Tuple. (Integer return code, string standard out, string standard error).
  """
  if isinstance(cmd, str):
    shell = True
  else:
    shell = False

  if env:
    environ = os.environ.copy()
    environ.update(env)
    env = environ

  p = subprocess.Popen(
      cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)

  if timeout <= 0:
    stdout, stderr = p.communicate()
  else:
    inactive = 0
    stdout = []
    stderr = []

    SetFileNonBlocking(p.stdout)
    SetFileNonBlocking(p.stderr)

    returncode = None

    while returncode is None:
      rlist, _, _ = select.select([p.stdout, p.stderr], [], [], 1.0)

      if not rlist:
        inactive += 1
        if inactive >= timeout:
          logging.error('cmd has timed out: %s', cmd)
          logging.error('Sending SIGTERM to PID=%s', p.pid)
          os.kill(p.pid, signal.SIGTERM)
          break  # note: this is a hard timeout, we don't read() again
      else:
        inactive = 0
        for fd in rlist:
          if fd is p.stdout:
            stdout.append(fd.read())
          elif fd is p.stderr:
            stderr.append(fd.read())

      returncode = p.poll()

    # if the process was just killed, wait for waitfor seconds.
    if inactive >= timeout and waitfor > 0:
      time.sleep(waitfor)
    # attempt to obtain returncode one last chance
    returncode = p.poll()
    stdout = ''.join(stdout)
    stderr = ''.join(stderr)

  return p.returncode, stdout, stderr


def GetPlistValue(key, secure=False, plist=None):
  """Returns the value of a given plist key.

  Args:
    key: string key to get from the plist.
    secure: boolean; True = munki secure plist, False = munki regular plist.
    plist: optional, str plist path to use, instead of Munki plist.
      Note, if plist is supplied, secure boolean is ignored.
  Returns:
    string value, or empty string if the key doesn't exist.
  """
  if not plist:
    if secure:
      plist = DEFAULT_SECURE_MANAGED_INSTALLS_PLIST_PATH
    else:
      plist = DEFAULT_MANAGED_INSTALLS_PLIST_PATH

  if OBJC_OK:
    pl = fpl.readPlist(plist)
    return pl.get(key, '')

  # get XML output of (potential) binary plist from plutil.
  exit_code, plist_xml, unused_err = Exec(
      ['/usr/bin/plutil', '-convert', 'xml1', '-o', '-', plist])
  if exit_code:
    logging.error('Failed to convert plist to xml1: %s', plist)
    return ''
  plist_contents = plistlib.readPlistFromString(plist_xml)
  return plist_contents.get(key, '')


def GetPlistDateValue(key, secure=False, plist=None, str_format=None):
  """Returns the UTC datetime of a given plist date key, or None if not found.

  Args:
    key: string key to get from the plist.
    secure: boolean; True = munki secure plist, False = munki regular plist.
    plist: optional, str plist path to use, instead of Munki plist.
      Note, if plist is supplied, secure boolean is ignored.
    str_format: optional, datetime.strftime format to return as str.
  Returns:
    if str_format=None, UTC datetime.datetime value  OR
    if str_format!=None, str from datetime.strftime(str_format, plist date)  OR
    if key is not found, None.
  """
  value = GetPlistValue(key, secure=secure, plist=plist)
  if hasattr(value, 'timeIntervalSince1970'):
    # FoundationPlist was used, so value is NSCFDate with local time offset.
    time_since_epoc = value.timeIntervalSince1970()
    value = datetime.datetime.utcfromtimestamp(time_since_epoc)
  elif not isinstance(value, datetime.datetime):
    if value:
      logging.error('plist date type unknown: %s %s', value, type(value))
    value = None

  if value and str_format:
    return value.strftime(str_format)
  else:
    return value


def GetUserSettings():
  """Read Google user settings from com.google.corp.machineinfo.

  Returns:
    dict, {} if there are no user settings defined
  Raises:
    ValueError if the user settings are malformed
  """
  return {}


def GetFacterFacts():
  """Return facter contents.

  Returns:
    dict, facter contents
  """
  return_code, stdout, unused_stderr = Exec(
      FACTER_CMD, timeout=300, waitfor=0.5)
  if return_code != 0:
    return {}

  # Iterate over the facter output and create a dictionary of the contents.
  facts = {}
  for line in stdout.splitlines():
    try:
      key, unused_sep, value = line.split(' ', 2)
      value = value.strip()
      facts[key] = value
    except ValueError:
      logging.warning('Ignoring invalid facter output line: %s', line)
  return facts


def GetSystemUptime():
  """Returns the system uptime.

  Returns:
    float seconds of uptime
  Raises:
    Error: if an error occurs in calculating uptime
  """
  libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))

  # 2 integers returned, might be 4 or 8 bytes each
  l = ctypes.c_int(16)
  buf = ctypes.create_string_buffer(16)

  try:
    r = libc.sysctlbyname(
        ctypes.c_char_p('kern.boottime'),
        buf, ctypes.byref(l), None, None)
  except AttributeError:
    raise Error('Cannot find sysctlbyname()')

  if r == 0 and l.value in [8, 16]:
    if l.value == 8:  # <=10.5
      fmt = 'II'
    else:             # >=10.6
      fmt = 'QQ'
    (since_s, since_ms) = struct.unpack(fmt, ctypes.string_at(buf, l))
    uptime = time.time() - float('%s.%s' % (since_s, since_ms))
  else:
    raise Error('sysctlbyname() returned %d, oldlenp=%d' % (r, l.value))

  return uptime


def GetDiskFree(path=None):
  """Return the bytes of free space.

  Args:
    path: str, optional, default '/'
  Returns:
    int, bytes in free space available
  """
  if path is None:
    path = '/'
  try:
    st = os.statvfs(path)
  except OSError as e:
    raise Error(str(e))

  return st.f_frsize * st.f_bavail  # f_bavail matches df(1) output


def GetClientIdentifier(runtype=None):
  """Assembles the client identifier based on information collected by facter.

  Args:
    runtype: str, optional, Munki runtype. i.e. auto, custom, manual, etc.
  Returns:
    dict client identifier.
  """
  facts = GetFacterFacts()

  uuid = (facts.get('certname', None) or
          facts.get('uuid', None) or _GetMachineInfoPlistValue('MachineUUID') or
          _GetHardwareUUID())
  uuid = uuid.lower()  # normalize uuid to lowercase.

  owner = (facts.get('primary_user', None) or
           _GetMachineInfoPlistValue('Owner') or _GetPrimaryUser() or
           _GetConsoleUser())

  hostname = (facts.get('sp_local_host_name', None) or
              facts.get('hostname', None) or _GetHostname())

  config_track = facts.get('configtrack', 'BROKEN')

  simian_track = (facts.get('simiantrack', None))

  # Apple SUS integration.
  applesus = facts.get('applesus', 'true').lower() == 'true'

  site = facts.get('site', None)

  os_version = platform.mac_ver()[0]  # tuple like: ('10.6.3', (...), 'i386')

  serial = facts.get('hardware_serialnumber', None) or _GetSerialNumber()

  # client_management_enabled facter support; defaults to enabled.
  mgmt_enabled = facts.get(
      'client_management_enabled', 'true').lower() == 'true'

  # Determine if the computer is on the corp network or not.
  on_corp = None
  on_corp_cmd = ''
  on_corp_cmd_config = '/etc/simian/on_corp_cmd'
  if not on_corp_cmd and os.path.isfile(on_corp_cmd_config):
    try:
      f = open(on_corp_cmd_config, 'r')
      on_corp_cmd = f.read()
      on_corp_cmd = on_corp_cmd.strip()
      f.close()
    except IOError as e:
      logging.exception(
          'Error reading %s: %s', on_corp_cmd_config, str(e))
  if on_corp_cmd:
    try:
      on_corp, unused_stdout, unused_stderr = Exec(
          on_corp_cmd, timeout=60, waitfor=0.5)
      # exit=0 means on corp, so reverse.
      on_corp = '%d' % (not on_corp)
    except OSError as e:
      # in this case, we don't know if on corp or not so don't log either.
      logging.exception('OSError calling on_corp_cmd: %s', str(e))
      on_corp = None

  # LastNotifiedDate comes as local time from FoundationPlist,
  # so convert to epoc timestamp then to UTC datetime.
  last_notified_datetime_str = GetPlistDateValue(
      'LastNotifiedDate', str_format=DATETIME_STR_FORMAT)

  # get uptime
  try:
    uptime = GetSystemUptime()
  except Error as e:
    uptime = 'ERROR: %s' % str(e)

  # get free space
  try:
    root_disk_free = GetDiskFree()
  except Error as e:
    root_disk_free = 'ERROR: %s' % str(e)

  # get user disk free
  user_disk_free = None
  if owner:
    try:
      # TODO(user): this may not be FileVault compatible, at least before
      # the user is logged in; investigate.
      user_dir_path = '/Users/%s/' % owner
      if os.path.isdir(user_dir_path):
        user_disk_free = GetDiskFree(user_dir_path)
    except Error as e:
      user_disk_free = 'ERROR: %s' % str(e)

  client_id = {
      'uuid': uuid,
      'owner': owner,
      'hostname': hostname,
      'serial': serial,
      'config_track': config_track,
      'track': simian_track,
      'applesus': applesus,
      'mgmt_enabled': mgmt_enabled,
      'site': site,
      'os_version': os_version,
      'client_version': GetClientVersion(),
      'on_corp': on_corp,
      'last_notified_datetime': last_notified_datetime_str,
      'runtype': runtype,
      'uptime': uptime,
      'root_disk_free': root_disk_free,
      'user_disk_free': user_disk_free,
  }
  return client_id


def DictToStr(d, delimiter=DELIMITER):
  """Returns a passed dict as a key=value string with a defined delimiter.

  Args:
    d: dict to convert to a string.
    delimiter: str delimiter to place between key/value pairs.

  Returns:
    String.  "uuid=<v>|owner=<v>|hostname=<v>|track=<v>" where "<v>" is the
    value. Any values that cannot be obtained default to an empty string.
  """
  out = []
  for key, value in d.iteritems():
    if value is None:
      out.append('%s=' % key)
    else:
      if isinstance(value, str):
        value = value.decode('utf-8')
      out.append('%s=%s' % (key, value))
  return delimiter.join(out).encode('utf-8')


def _SetCustomCatalogURL(catalog_url):
  """Sets Software Update's CatalogURL to custom value."""
  key = 'SimianCatalogURL'
  if munkicommon.pref(key) == catalog_url:
    return
  munkicommon.set_pref(key, catalog_url)

  os_version_tuple = munkicommon.getOsVersion(as_tuple=True)
  # set custom catalog url on each preflight for apple updates
  if os_version_tuple >= (10, 11):
    Exec(['/usr/sbin/softwareupdate', '--set-catalog', catalog_url])

  Exec([
      '/usr/bin/defaults', 'write', APPLE_SUS_PLIST, 'CatalogURL', catalog_url])


def UpdateAppleSUSCatalog(client):
  """Fetches an Apple Software Update Service catalog from the server."""

  url = GetServerURL()

  resp = client.Do(
      'POST', '%s/applesus/' % url,
      headers={MUNKI_CLIENT_ID_HEADER_KEY: DictToStr(GetClientIdentifier())})

  applesus_url = '%s/applesus/%s' % (url, resp.body)

  _SetCustomCatalogURL(applesus_url)


def GetAuth1Token():
  """Returns an Auth1Token for use with server authentication."""
  if AUTH1_TOKEN:
    return AUTH1_TOKEN

  if not OBJC_OK:
    logging.error('Objective-C bindings not available.')
    return None

  pref_value = Foundation.CFPreferencesCopyAppValue(
      'AdditionalHttpHeaders', 'ManagedInstalls')
  if pref_value is None:
    logging.error('GetAuth1Token(): AdditionalHttpHeaders not present.')
    return None

  header = 'Cookie: Auth1Token='
  for h in pref_value:
    if h.startswith(header):
      logging.debug('GetAuth1Token(): found %s', h)
      token = h[len(header):]
      if token.find(';') > -1:
        token = token[0:token.find(';')]
      token = str(token)
      return token

  logging.error('GetAuth1Token(): AdditionalHttpHeaders lacks a token.')
  return None


def Flatten(o):
  """Flatten pyobjc objects into Python native equivalents.

  Args:
    o: any object
  Returns:
    object in Python native equivalent (possibly unchanged)
  """
  if o is None or not OBJC_OK:
    pass
  elif type(o, Foundation.NSCFDictionary):
    n = {}
    for k, v in o.iteritems():
      n[Flatten(k)] = Flatten(v)
    o = n
  elif isinstance(o, Foundation.NSCFArray):
    n = []
    for i in xrange(len(o)):
      n.append(Flatten(o[i]))
    o = n
  elif isinstance(o, objc.pyobjc_unicode):
    o = unicode(o)
  elif hasattr(o, 'initWithInteger_'):
    o = int(o)
  return o


def GetManagedInstallReport(install_report_path=None):
  """Returns the ManagedInstallReport.plist plist object."""
  if not install_report_path:
    managed_installs_dir = munkicommon.pref('ManagedInstallDir')
    install_report_path = os.path.join(
        managed_installs_dir, 'ManagedInstallReport.plist')
  try:
    install_report = fpl.readPlist(install_report_path)
  except fpl.NSPropertyListSerializationException as e:
    logging.debug('Error reading %s : %s', install_report_path, str(e))
    return {}, install_report_path
  return install_report, install_report_path


def GetMunkiName(item_dict):
  """Returns the display_name or name of a Munki package."""
  return item_dict.get('display_name', item_dict.get('name')).encode('utf-8')


def GetMunkiNameAndVersion(item_dict):
  """Returns the "(display_name|name)-version" Munki name."""
  name = GetMunkiName(item_dict).decode('utf-8')
  munki_name = u'%s-%s' % (name, item_dict.get('version_to_install', ''))
  return munki_name.encode('utf-8')


def GetRemainingPackagesToInstall():
  """Returns a list of string packages that are remaining to install."""
  install_report, unused_path = GetManagedInstallReport()
  if not install_report:
    return []

  install_results = install_report.get('InstallResults', [])
  just_installed = set(
      [GetMunkiName(d) for d in install_results if hasattr(d, 'keys')])

  pkgs_to_install_dicts = install_report.get('ItemsToInstall', [])
  pkgs_to_install = [GetMunkiNameAndVersion(d) for d in pkgs_to_install_dicts
                     if GetMunkiName(d) not in just_installed]

  apple_to_install_dicts = install_report.get('AppleUpdates', [])
  apple_updates_to_install = [
      GetMunkiNameAndVersion(d) for d in apple_to_install_dicts
      if GetMunkiName(d) not in just_installed]

  return pkgs_to_install, apple_updates_to_install


def _UploadManagedInstallReport(client, on_corp, install_report):
  """Reports any installs, updates, uninstalls back to Simian server.

  Args:
    client: SimianAuthClient.
    on_corp: str, on_corp status from GetClientIdentifier.
    install_report: plist object for ManagedInstallsReport.plist.
  """
  if not install_report:
    return

  installs = install_report.get('InstallResults', [])  # includes updates.
  removals = install_report.get('RemovalResults', [])
  problem_installs = install_report.get('ProblemInstalls', [])

  # encode all strings to utf-8 for unicode character support.
  for item_list in [removals]:
    for i in xrange(len(item_list)):
      item_list[i] = unicode(item_list[i]).encode('utf-8')

  # convert dict problems to strings, and encode as utf-8.
  for i in xrange(len(problem_installs)):
    # TODO(user): send dict to server so details can be stored separately:
    #    problem_installs[i] = DictToStr(problem_installs[i])
    p = problem_installs[i]
    if hasattr(p, 'keys'):
      p = u'%s: %s' % (p.get('name', ''), p.get('note', ''))
    problem_installs[i] = p.encode('utf-8')

  for i in xrange(len(installs)):
    # If 'time' exists, convert it to an epoc timestamp.
    install_time = installs[i].get('time', None)
    if hasattr(install_time, 'timeIntervalSince1970'):
      installs[i]['time'] = install_time.timeIntervalSince1970()
    # TODO(user): convert DictToStr to JSON, here and on the server, in
    #     //mac/munki/handlers/reports.py:_LogInstalls
    installs[i] = DictToStr(installs[i])

  if installs or removals or problem_installs:
    data = {
        'on_corp': on_corp,
        'installs': installs,
        'removals': removals,
        'problem_installs': problem_installs,
    }
    client.PostReport('install_report', data)


def UploadAllManagedInstallReports(client, on_corp):
  """Uploads any installs, updates, uninstalls back to Simian server.

  Args:
    client: A SimianAuthClient.
    on_corp: str, on_corp status from GetClientIdentifier.
  """
  # Report installs from the ManagedInstallsReport archives.
  archives_dir = os.path.join(munkicommon.pref('ManagedInstallDir'), 'Archives')
  if os.path.isdir(archives_dir):
    for fname in os.listdir(archives_dir):
      if not fname.startswith('ManagedInstallReport-'):
        continue
      install_report_path = os.path.join(archives_dir, fname)
      if not os.path.isfile(install_report_path):
        continue
      install_report, _ = GetManagedInstallReport(
          install_report_path=install_report_path)
      try:
        _UploadManagedInstallReport(client, on_corp, install_report)
        try:
          os.unlink(install_report_path)
        except (IOError, OSError):
          logging.warning(
              'Failed to delete ManagedInstallsReport.plist: %s',
              install_report_path)
      except ServerRequestError:
        logging.exception('Error uploading ManagedInstallReport installs.')

  # Report installs from the current ManagedInstallsReport.plist.
  install_report, install_report_path = GetManagedInstallReport()
  try:
    _UploadManagedInstallReport(client, on_corp, install_report)
    # Clear reportable information now that is has been published.
    install_report['InstallResults'] = []
    install_report['RemovalResults'] = []
    install_report['ProblemInstalls'] = []
    fpl.writePlist(install_report, install_report_path)
  except ServerRequestError:
    logging.exception('Error uploading ManagedInstallReport installs.')


def UploadClientLogFiles(client):
  """Uploads the Munki client log files to the server.

  Args:
    client: A SimianAuthClient object.
  """
  managed_installs_dir = munkicommon.pref('ManagedInstallDir')
  log_file_paths = [
      os.path.join(managed_installs_dir, 'InstallInfo.plist'),
      os.path.join(managed_installs_dir, 'ManagedInstallReport.plist'),
      os.path.join(managed_installs_dir, 'Logs', 'ManagedSoftwareUpdate.log'),
      '/Users/Shared/.SelfServeManifest',
      '/var/log/system.log',
      '/var/log/debug.log',
      '/var/log/install.log',
  ]
  for log_file_path in log_file_paths:
    if os.path.exists(log_file_path):
      client.UploadFile(log_file_path, 'log')

  # Upload output of 'ps -ef'.
  return_code, stdout, _ = Exec(['/bin/ps', '-ef'])
  if not return_code:
    path = os.path.join(
        tempfile.mkdtemp(prefix='munki_ps_ef_output_', dir='/tmp'),
        'ps_ef_output')
    f = open(path, 'w')
    f.write(stdout)
    f.close()
    client.UploadFile(path, 'log')


def KillHungManagedSoftwareUpdate():
  """Kill hung managedsoftwareupdate instances, if any can be found.

  Returns:
    True if a managedsoftwareupdate instance was killed, False otherwise.
  """
  rc, stdout, stderr = Exec(['/bin/ps', '-eo', 'pid,ppid,lstart,command'])
  if rc != 0 or not stdout or stderr:
    return False

  pids = {}
  msu_pids = []

  for l in stdout.splitlines():
    a = l.split()
    if len(a) < 8:
      continue

    try:
      pids[int(a[0])] = {
          'ppid': int(a[1]),
          'lstart': datetime.datetime(*time.strptime(' '.join(a[2:7]))[0:7]),
          'command': '\t'.join(a[7:]),
      }
    except ValueError:
      continue

    if re.search(r'(MacOS\/Python|python)', a[7], re.IGNORECASE):
      if len(a) > 8 and a[8].find('managedsoftwareupdate') > -1:
        msu_pids.append(int(a[0]))

  now = datetime.datetime.now()
  kill = []

  for pid in msu_pids:
    if (now - pids[pid]['lstart']) >= HUNG_MSU_TIMEOUT:
      for opid in pids:
        if pids[opid]['ppid'] == pid:
          kill.append(opid)  # child
      kill.append(pid)  # parent last

  for pid in kill:
    if pid == 1:  # sanity check
      continue
    try:
      logging.warning('Sending SIGKILL to pid %d', pid)
      os.kill(pid, signal.SIGKILL)
    except OSError as e:
      # if the process died between ps and now we're OK, otherwise log error.
      if e.args[0] != errno.ESRCH:
        logging.warning('OSError on kill(%d, SIGKILL): %s', pid, str(e))

  return bool(len(kill))


def Pkill(process, sig='-SIGKILL', waitfor=0):
  """Kills a process by exact name with 'pkill'.

  Useful for killing installd, effectively terminating any hung installations.

  Args:
    process: name of process to kill, like 'installd'.
    sig: string, signal to send, default of '-SIGKILL'.
    waitfor: int or float, if >0, Pkill() will wait waitfor seconds
      before returning.
  Returns:
    True if process could be killed, False otherwise.
  """
  logging.warning('Sending %s to %s', sig, process)
  cmd = ['/usr/bin/pkill', sig, '-x', process]
  rc, _, _ = Exec(cmd)
  if rc == 0:
    logging.warning('Killed %s', process)
    time.sleep(waitfor)
    return True
  else:
    logging.error('Could not kill %s!', process)
    return False


def RepairClient():
  """Downloads and installs a new Simian client.

  Raises:
    RepairClientError: there was an error repairing this client.
  """
  url = GetServerURL()
  logging.info('Fetching repair client from: %s/repair', url)
  # TODO(user): figure out a way to not specify filename, then add a version
  # check so if the downloaded client is the same version that is running the
  # repair will just abort.
  download_path = os.path.join(
      tempfile.mkdtemp(prefix='munki_repair_dmg_', dir='/tmp'),
      'munkiclient.dmg')
  mount_path = tempfile.mkdtemp(prefix='munki_repair_client_', dir='/tmp')

  try:
    updatecheck.getResourceIfChangedAtomically('%s/repair' % url, download_path)
  except fetch.MunkiDownloadError as e:
    raise RepairClientError(
        u'MunkiDownloadError getting Munki client: %s' % e)

  return_code, unused_stdout, stderr = Exec(
      ['/usr/bin/hdiutil', 'attach', '-mountpoint', mount_path, '-nobrowse',
       '-readonly', download_path])

  logging.info('Mounted munki repair client dmg at %s.', mount_path)
  if return_code != 0:
    raise RepairClientError('Failed to attach repair client dmg with ret %s. '
                            'Error: %s' % (return_code, stderr))

  if not os.path.isdir(mount_path):
    raise RepairClientError('Mount path not found:' % mount_path)

  file_list = os.listdir(mount_path)
  for file_name in file_list:
    if re.match(r'^(munkitools.*|simian.*)\.pkg$', file_name):
      installer_file = os.path.join(mount_path, file_name)

  cmd = ['/usr/sbin/installer', '-pkg', installer_file, '-target', '/']
  logging.info('Trying to install repair client with %s.', ' '.join(cmd))
  return_code, unused_stdout, stderr = Exec(cmd)

  if return_code != 0:
    raise RepairClientError(
        'Failed to install pkg with ret %s. Error: %s' % (return_code, stderr))

  return_code, unused_stdout, unused_stderr = Exec(
      ['/usr/bin/hdiutil', 'detach', mount_path, '-force'])

  if return_code != 0:
    logging.warning('Could not detach %s!', mount_path)

  # If we've just repaired, kill any hung managedsofwareupdate instances, as
  # that may be the main reason we needed to repair in the first place.
  KillHungManagedSoftwareUpdate()
