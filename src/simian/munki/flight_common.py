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

"""Custom preflight/postflight common module."""




import cPickle as Pickle
import ctypes
import ctypes.util
import datetime
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
import sys
import time
import urllib
import urlparse
import version
# Place all ObjC-dependent imports in this try/except block.
# Silently work around missing modules within this module using OBJC_OK!
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


AUTH_BINARY = '/usr/local/bin/simianauth'
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
DEFAULT_FACTER_CACHE_PATH = (
    '/Library/Managed Installs/facter.cache')
DEFAULT_FACTER_CACHE_TIME = datetime.timedelta(hours=3)
# InstallResults legacy string matching regex.
LEGACY_INSTALL_RESULTS_STRING_REGEX = (
    '^Install of (.*)-(\d+.*): (SUCCESSFUL|FAILED with return code: (\-?\d+))$')


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

  # Client should upload logs to the server.
  UPLOAD_LOGS = 'UPLOAD_LOGS'


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
    match = re.search('^\s+Serial Number[^:]+: (.*)$', stdout, re.MULTILINE)
    if match:
      return match.group(1)
  return ''


def _GetHardwareUUID():
  """Returns the str hardware UUID from system_profiler, or '' if not found."""
  return_code, stdout, unused_stderr = Exec(
      'system_profiler SPHardwareDataType')
  if return_code == 0 and stdout:
    match = re.search('^\s+Hardware UUID: (.*)$', stdout, re.MULTILINE)
    if match:
      return match.group(1)
  return ''


def _GetPrimaryUser():
  """Returns the str username of the user that has logged in the most."""
  return_code, stdout, unused_stderr = Exec(['last', '-100'])
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


def Exec(cmd, timeout=0, waitfor=0):
  """Executes a process and returns exit code, stdout, stderr.

  Args:
    cmd: str or sequence, command and optional arguments to execute.
    timeout: int or float, if >0, Exec() will stop waiting for output
      after timeout seconds and kill the process it started.  return code
      might be undefined, or -SIGTERM, use waitfor to make sure to obtain it.
      values <1 will be crudely rounded off because of select() sleep time.
    waitfor: int or float, if >0, Exec() will wait waitfor seconds
      before asking for the process exit status one more time.
  Returns:
    Tuple. (Integer return code, string standard out, string standard error).
  """
  if type(cmd) is str:
    shell = True
  else:
    shell = False

  p = subprocess.Popen(
      cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)

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
      ['plutil', '-convert', 'xml1', '-o', '-', plist])
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
  elif type(value) is not datetime.datetime:
    if value:
      logging.error('plist date type unknown: %s %s', value, type(value))
    value = None

  if value and str_format:
    return value.strftime(str_format)
  else:
    return value




def CacheFacterContents():
  """Run facter -p to cache its contents, and also return them.

  Returns:
    dict, facter contents (which have now also been cached)
  """
  return_code, stdout, unused_stderr = Exec(
      FACTER_CMD, timeout=60, waitfor=0.5)

  # If execution of factor was successful build the client identifier
  if return_code != 0:
    return {}

  facts = {}

  # Iterate over the facter output and create a dictionary of the output
  lines = stdout.splitlines()
  for line in lines:
    (key, unused_sep, value) = line.split(' ', 2)
    value = value.strip()
    facts[key] = value

  try:
    f = open(DEFAULT_FACTER_CACHE_PATH, 'w')
  except IOError:
    return facts
  Pickle.dump(facts, f)
  f.close()
  return facts


def GetMachineInfoFromFacter():
  """Return facter contents.

  Returns:
    dict, facter contents
  """
  now = datetime.datetime.now()
  facter = {}

  try:
    st = os.stat(DEFAULT_FACTER_CACHE_PATH)
    if (os.geteuid() == 0 and st.st_uid != 0) or (
        os.geteuid() != 0 and st.st_uid != 0 and os.geteuid() != st.st_uid):
      # don't trust this file.  be paranoid.
      cache_mtime = datetime.datetime.fromtimestamp(0)
    else:
      cache_mtime = datetime.datetime.fromtimestamp(st.st_mtime)
  except OSError:
    cache_mtime = datetime.datetime.fromtimestamp(0)

  if now - cache_mtime < DEFAULT_FACTER_CACHE_TIME:
    try:
      f = open(DEFAULT_FACTER_CACHE_PATH, 'r')
      facter = Pickle.load(f)
      f.close()
    except (ImportError, EOFError, IOError, Pickle.UnpicklingError):
      facter = {}

  if not facter:
    facter = CacheFacterContents()

  return facter


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
  except OSError, e:
    raise Error(str(e))

  return st.f_frsize * st.f_bavail  # f_bavail matches df(1) output


def GetClientIdentifier(runtype=None):
  """Assembles the client identifier based on information collected by facter.

  Args:
    runtype: str, optional, Munki runtype. i.e. auto, custom, manual, etc.
  Returns:
    dict client identifier.
  """
  facts = GetMachineInfoFromFacter()

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

  simian_track = (facts.get('simiantrack', None) or
                 _GetMachineInfoPlistValue('SimianTrack'))

  # Apple SUS integration.
  applesus = facts.get('applesus', 'true').lower() == 'true'

  site = facts.get('site', None)
  office = facts.get('location', None)

  os_version = platform.mac_ver()[0]  # tuple like: ('10.6.3', (...), 'i386')

  serial = facts.get('hardware_serialnumber', None) or _GetSerialNumber()

  # client_management_enabled facter support; defaults to enabled.
  mgmt_enabled = '%d' % (
      facts.get('client_management_enabled', 'true') == 'true')

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
    except IOError, e:
      logging.exception(
          'Error reading %s: %s', on_corp_cmd_config, str(e))
  if on_corp_cmd:
    try:
      on_corp, unused_stdout, unused_stderr = Exec(
          on_corp_cmd, timeout=60, waitfor=0.5)
      # exit=0 means on corp, so reverse.
      on_corp = '%d' % (not on_corp)
    except OSError, e:
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
  except Error, e:
    uptime = 'ERROR: %s' % str(e)

  # get free space
  try:
    root_disk_free = GetDiskFree()
  except Error, e:
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
    except Error, e:
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
      'office': office,
      'os_version': os_version,
      'client_version': GetClientVersion(),
      'on_corp': on_corp,
      'last_notified_datetime': last_notified_datetime_str,
      'runtype': runtype,
      'uptime': uptime,
      'root_disk_free': root_disk_free,
      'user_disk_free': user_disk_free,
      'global_uuid': '__GLOBAL_UUID__',  # replaced by simianauth
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
      if type(value) is str:
        value = value.decode('utf-8')
      out.append('%s=%s' % (key, value))
  return delimiter.join(out).encode('utf-8')


def GetAppleSUSCatalog():
  """Fetches an Apple Software Update Service catalog from the server."""
  url = GetServerURL()
  try:
    updatecheck.getResourceIfChangedAtomically(
        '%s/applesus/' % url, APPLE_SUS_CATALOG)
    # Update the CatalogURL setting in com.apple.SoftwareUpdate.plist.
    sus_catalog = fpl.readPlist(APPLE_SUS_PLIST)
    sus_catalog['CatalogURL'] = urlparse.urljoin(
        'file://localhost/', urllib.quote(APPLE_SUS_CATALOG))
    fpl.writePlist(sus_catalog, APPLE_SUS_PLIST)
  except fetch.MunkiDownloadError:
    logging.exception('MunkiDownloadError getting Apple SUS catalog.')


def PostReportToServer(
    report_type, params,
    token=None, login=False, logout=True, raise_exc=False):
  """POSTs report to server.

  Args:
    report_type: str report type.
    params: dict of data to POST.
    token: optional str auth token to use.
    login: optional boolean; True to pass --login to simianauth binary.
        Default False. If True, token is ignored.
    logout: optional boolean. True to logout after posting the report.
    raise_exc: bool, optional, True to raise exceptions on non 0 status
      from underlying server request handler, False (default) to nicely
      log and ignore.
  Returns:
    None or a status string like 'FORCE_CONTINUE'
  Raises:
    ServerRequestError: if raise_exc is True and a server exception occurs
  """
  params['_report_type'] = report_type  # add report type to post data.
  # encode post dict to url query string; doseq=True for sequence support.
  params = urllib.urlencode(params, doseq=True)
  params = (
      '--report',
      'feedback:OK=0:%s=99:body:%s' % (ReportFeedback.FORCE_CONTINUE, params))
  response = None
  try:
    try:
      if token:
        PerformServerRequest(
            params, token=token, login=login, logout=logout, raise_exc=True)
      else:
        PerformServerRequest(
            params, login=login, logout=logout, raise_exc=True)
    except OSError, e:
      if e.args[1] == 99:
        response = ReportFeedback.FORCE_CONTINUE
      else:
        raise ServerRequestError(e)
  except ServerRequestError, e:
    if raise_exc is True:
      raise
    # gracefully allow report posting failures, but display notification.
    logging.exception('Failure post to report to server: %s', str(e))
  return response


def PerformServerRequest(
    params=None, token=DEFAULT_SECURE_MANAGED_INSTALLS_PLIST_PATH, login=False,
    logout=False, raise_exc=False):
  """Performs a urllib2 request to the passed URL.

  Args:
    params: sequence, optional, params to pass to auth binary.
    token: str, optional, auth token to use.
    login: bool, optional, True to pass --login to simianauth binary.
        Default False. If True, token is ignored.
    logout: bool, optional, True to logout after any other commands.
    raise_exc: bool, optional, True to raise exceptions on non 0 status
      from underlying server request handler, False (default) to nicely
      log and ignore.
  Returns:
    Str response from server.
  """
  script_dir = os.path.realpath(os.path.dirname(sys.argv[0]))
  cmd = [os.path.join(script_dir, AUTH_BINARY)]

  url = GetServerURL()
  cmd.append('--server')
  cmd.append(url)

  if login:
    cmd.append('--login')
  else:
    cmd.append('--token')
    cmd.append(token)

  if params:
    cmd.extend(params)
  if logout:
    cmd.append('--logout')

  try:
    rc, stdout, stderr = Exec(cmd, timeout=90, waitfor=0.5)
    if rc != 0:
      raise OSError('Exec %d: %s' % (rc, stderr), rc)
  except OSError, e:
    if raise_exc is True:
      raise
    # gracefully allow failed server requests, but display error.
    logging.exception('Error contacting server: %s', str(e))

  return stdout


def Flatten(o):
  """Flatten pyobjc objects into Python native equivalents.

  Args:
    o: any object
  Returns:
    object in Python native equivalent (possibly unchanged)
  """
  if o is None or not OBJC_OK:
    pass
  elif type(o) is Foundation.NSCFDictionary:
    n = {}
    for k, v in o.iteritems():
      n[Flatten(k)] = Flatten(v)
    o = n
  elif type(o) is Foundation.NSCFArray:
    n = []
    for i in xrange(len(o)):
      n.append(Flatten(o[i]))
    o = n
  elif type(o) is objc.pyobjc_unicode:
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
  except fpl.NSPropertyListSerializationException, e:
    logging.debug('Error reading %s : %s', install_report_path, str(e))
    return {}, install_report_path
  return install_report, install_report_path


def GetInstallResults(install_results):
  """Returns list of dicts for InstallResults list of str or NSCFDictionary.

  Args:
    install_results: list of strs or NSCFDictionary.
  Returns:
    list of strings or list of dict
  """
  out = []
  for item in install_results:
    if not hasattr(item, 'keys'):
      # if any old-style InstallResults strings exist, convert them to dict.
      try:
        m = re.search(LEGACY_INSTALL_RESULTS_STRING_REGEX, item)
        if m.group(3) == 'SUCCESSFUL':
          status = 0
        else:
          status = m.group(4)
        item = {
            'name': m.group(1), 'version': m.group(2), 'applesus': False,
            'status': status, 'duration_seconds': None,
            'download_kbytes_per_sec': None,
        }
      except (IndexError, AttributeError):
        item = {
            'name': item, 'version': '', 'applesus': False,
            'status': 'UNKNOWN', 'duration_seconds': None,
            'download_kbytes_per_sec': None,
        }
    out.append(item)
  return out


def GetMunkiName(item_dict):
  """Returns the display_name or name of a Munki package."""
  return item_dict.get('display_name', item_dict.get('name')).encode('utf-8')


def GetMunkiNameAndVersion(item_dict):
  """Returns the "(display_name|name)-version" Munki name."""
  name = GetMunkiName(item_dict)
  munki_name = '%s-%s' % (name, item_dict.get('version_to_install', ''))
  return munki_name.encode('utf-8')


def GetRemainingPackagesToInstall():
  """Returns a list of string packages that are remaining to install."""
  install_report, unused_path = GetManagedInstallReport()
  if not install_report:
    return []

  install_results = install_report.get('InstallResults', [])
  just_installed = [i['name'] for i in install_results
                    if hasattr(i, 'keys')]

  pkgs_to_install_dicts = install_report.get('ItemsToInstall', [])
  pkgs_to_install = [GetMunkiNameAndVersion(d) for d in pkgs_to_install_dicts
                     if GetMunkiName(d) not in just_installed]

  apple_to_install_dicts = install_report.get('AppleUpdates', [])
  apple_updates_to_install = [
      GetMunkiNameAndVersion(d) for d in apple_to_install_dicts
      if GetMunkiName(d) not in just_installed]

  return pkgs_to_install, apple_updates_to_install


def _UploadManagedInstallReport(on_corp, install_report, logout=False):
  """Reports any installs, updates, uninstalls back to Simian server.

  If no reports of installs/updates/uninstalls exist to report,
  then this function only contacts the server if logout is True.

  Args:
    on_corp: str, on_corp status from GetClientIdentifier.
    install_report: plist object for ManagedInstallsReport.plist.
    logout: bool, default False, whether to logout or not.
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
    p = problem_installs[i]
    if hasattr(p, 'keys'):
      p = u'%s: %s' % (p.get('name', ''), p.get('note', ''))
    problem_installs[i] = p.encode('utf-8')

  # convert any InstallResults entries to standardized strings.
  installs = GetInstallResults(installs)
  for i in xrange(len(installs)):
    # If 'time' exists, convert it to an epoc timestamp.
    install_time = installs[i].get('time', None)
    if hasattr(install_time, 'timeIntervalSince1970'):
      installs[i]['time'] = install_time.timeIntervalSince1970()
    # TODO(user): if we moved all of this code to simianauth, we could just use
    #      JSON instead of doing all this DictToStr nonsense just to pass it
    #      over the commandline.
    install_string = DictToStr(installs[i])
    installs[i] = install_string.encode('utf-8')

  if installs or removals or problem_installs:
    data = {
        'on_corp': on_corp,
        'installs': installs,
        'removals': removals,
        'problem_installs': problem_installs,
    }
    PostReportToServer('install_report', data, logout=logout, raise_exc=True)
  else:
    if logout:
      PerformServerRequest(logout=True)


def UploadAllManagedInstallReports(on_corp, logout=False):
  """Uploads any installs, updates, uninstalls back to Simian server.

  If no reports of installs/updates/uninstalls exist to report,
  then this function only contacts the server if logout is True.

  Args:
    on_corp: str, on_corp status from GetClientIdentifier.
    logout: bool, default False, whether to logout or not when finished.
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
        _UploadManagedInstallReport(on_corp, install_report)
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
    _UploadManagedInstallReport(on_corp, install_report, logout=logout)
    # Clear reportable information now that is has been published.
    install_report['InstallResults'] = []
    install_report['RemovalResults'] = []
    install_report['ProblemInstalls'] = []
    fpl.writePlist(install_report, install_report_path)
  except ServerRequestError:
    logging.exception('Error uploading ManagedInstallReport installs.')


def UploadClientLogFiles():
  """Uploads the Munki client log files to the server."""
  params = []

  # Upload select Munki logs.
  managed_installs_dir = munkicommon.pref('ManagedInstallDir')
  log_file_names = ['ManagedSoftwareUpdate.log']
  for log_file_name in log_file_names:
    log_file_path = os.path.join(managed_installs_dir, 'Logs', log_file_name)
    if log_file_path:
      params.append('--uploadfile')
      params.append(log_file_path)

  # Upload system.log.
  params.append('--uploadfile')
  params.append('/var/log/system.log')

  # Upload install.log.
  params.append('--uploadfile')
  params.append('/var/log/install.log')

  # Inform simianauth which type of file(s) we're uploading.
  params.append('--uploadfiletype')
  params.append('log')

  PerformServerRequest(params)


def RepairClient():
  """Downloads and installs a new Simian client.

  Raises:
    RepairClientError: there was an error repairing this client.
  """
  url = GetServerURL()
  # TODO(user): figure out a way to not specify filename, then add a version
  # check so if the downloaded client is the same version that is running the
  # repair will just abort.
  download = '/tmp/munkiclient.dmg'
  try:
    logging.info('Fetching repair client from: %s/repair', url)
    updatecheck.getResourceIfChangedAtomically('%s/repair' % url, download)
  except fetch.MunkiDownloadError, e:
    raise RepairClientError(
        'MunkiDownloadError getting Munki client: %s' % str(e))

  return_code, stdout, stderr = Exec(
      ['/usr/bin/hdiutil', 'attach', '-mountRandom', '/tmp', '-nobrowse',
       '-plist', '/tmp/munkiclient.dmg'])
  if return_code != 0:
    raise RepairClientError(
        'Failed to attach dmg with ret %s. Error: %s' % (return_code, stderr))

  # Get the mount point of the the mounted dmg; NOTE: if the munki dmg ever has
  # multiple mount points then this will need adjusting.
  mount_point = None
  pl = fpl.readPlistFromString(stdout)
  for item in pl['system-entities']:
    if 'mount-point' in item:
      mount_point = item['mount-point']
  if not mount_point or not os.path.isdir(mount_point):
    raise RepairClientError('Mount point not found:' % mount_point)

  return_code, stdout, stderr = Exec(
      ['/usr/sbin/installer', '-pkg', '%s/munkitools.pkg' % mount_point,
       '-target', '/'])
  if return_code != 0:
    raise RepairClientError(
        'Failed to install pkg with ret %s. Error: %s' % (return_code, stderr))

  unused_return_code, unused_stdout, unused_stderr = Exec(
      ['/usr/bin/hdiutil', 'detach', mount_point, '-force'])