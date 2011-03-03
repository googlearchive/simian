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
import datetime
import logging
import os
import platform
import re
import struct
import subprocess
import sys
import time
import urllib
import ctypes
import ctypes.util
import plistlib  # cannot read binary plists, be careful!
import version
# Place all ObjC-dependent imports in this try/except block.
# Silently work around missing modules within this module using OBJC_OK!
try:
  from munkilib import FoundationPlist as fpl
  from munkilib import munkicommon
  from munkilib import updatecheck
  import SystemConfiguration as sys_config
  import Foundation
  import objc
  OBJC_OK = True
except ImportError:
  # Python does not have ObjC bindings.
  OBJC_OK = False


AUTH_BINARY = '/usr/local/bin/simianauth'
FACTER_CMD = '/usr/local/bin/simianfacter'
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


class Error(Exception):
  """Class for domain specific exceptions."""


class ServerRequestError(Error):
  """Error issuing request to server."""


class ReportFeedback(object):
  """Class container for feedback status constants."""

  # Client should proceed as normally defined.
  OK = 'OK'

  # Client should NOT exit and instead continue, even if this means masking
  # an error which it would usually stop running because of.
  FORCE_CONTINUE = 'FORCE_CONTINUE'

  # Client should exit instead of continuing as normal.
  EXIT = 'EXIT'


def GetClientVersion():
  """Returns the str Munki + Simian version."""
  if not OBJC_OK:
    return ''
  return '%s %s' % (munkicommon.get_version(), version.VERSION)


def _GetConsoleUser():
  """Returns the logged in console username, or None if nobody is logged in."""
  print >>sys.stderr, 'facter primary_user empty; fetching from sys_config'
  if OBJC_OK:
    # this returns a tuple of (username, uid, gid)
    # if no console user is logged in, it'll be (None, 0, 0)
    return sys_config.SCDynamicStoreCopyConsoleUser(None, None, None)[0] or ''
  else:
    return None


def _GetHostname():
  """Returns the hostname from SystemConfiguration."""
  print >>sys.stderr, 'facter hostname empty; fetching from sys_config'
  if OBJC_OK:
    # this returns a tuple of (computer name, useless int)
    return sys_config.SCDynamicStoreCopyComputerName(None, None)[0]
  else:
    return None

def _GetHardwareUUID():
  """Returns the str hardware UUID from system_profiler, or '' if not found."""
  return_code, stdout, unused_stderr = Exec(
      'system_profiler | grep "Hardware UUID"')  # only compatible with 10.5.8+
  if return_code == 0 and stdout:
    match = re.search('Hardware UUID: (.*)$', stdout, re.IGNORECASE)
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
    users_list.sort(cmp=lambda x,y: cmp(users[x], users[y]), reverse=True)
    return users_list[0]
  return ''


def _GetMachineInfoPlistValue(key):
  """Returns value of given key in the machineinfo plist, or '' if not found."""
  return ''


def Exec(cmd):
  """Executes a process and returns exit code, stdout, stderr.

  Args:
    cmd: str or sequence, command and optional arguments to execute.

  Returns:
    Tuple. (Integer return code, string standard out, string standard error).
  """
  if type(cmd) is str:
    shell = True
  else:
    shell = False
  p = subprocess.Popen(
    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
  stdout, stderr = p.communicate()
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
    print >> sys.stderr, 'Failed to convert plist to xml1: %s' % plist
    return ''
  plist_contents = plistlib.readPlistFromString(plist_xml)
  return plist_contents.get(key, '')


def GetPlistDateValue(key, secure=False, plist=None):
  """Returns the UTC datetime of a given plist date key, or None if not found.

  Args:
    key: string key to get from the plist.
    secure: boolean; True = munki secure plist, False = munki regular plist.
    plist: optional, str plist path to use, instead of Munki plist.
      Note, if plist is supplied, secure boolean is ignored.
  Returns:
    UTC datetime.datetime value; None if key is not found.
  """
  value = GetPlistValue(key, secure=secure, plist=plist)
  if hasattr(value, 'timeIntervalSince1970'):
    # FoundationPlist was used, so value is NSCFDate with local time offset.
    time_since_epoc = value.timeIntervalSince1970()
    return datetime.datetime.utcfromtimestamp(time_since_epoc)
  elif type(value) is datetime.datetime:
    return value
  else:
    if value:  # if not empty string or None, print warning.
      print >>sys.stderr, 'plist date type unknown: %s %s' % (
          value, type(value))
    return None




def CacheFacterContents():
  """Run facter -p to cache its contents, and also return them.

  Returns:
    dict, facter contents (which have now also been cached)
  """
  return_code, stdout, unused_stderr = Exec(FACTER_CMD)

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


def GetClientIdentifier():
  """Assembles the client identifier based on information collected by facter.

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
      print >>sys.stderr, (
          'Error reading %s: %s' % (on_corp_cmd_config, str(e)))
  if on_corp_cmd:
    try:
      on_corp, unused_stdout, unused_stderr = Exec(on_corp_cmd)
      # exit=0 means on corp, so reverse.
      on_corp = '%d' % (not on_corp)
    except OSError, e:
      # in this case, we don't know if on corp or not so don't log either.
      print >>sys.stderr, 'OSError calling on_corp_cmd: %s', str(e)
      on_corp = None

  # LastNotifiedDate comes as local time from FoundationPlist,
  # so convert to epoc timestamp then to UTC datetime.
  last_notified_datetime = GetPlistDateValue('LastNotifiedDate')

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
      'config_track': config_track,
      'track': simian_track,
      'applesus': applesus,
      'site': site,
      'office': office,
      'os_version': os_version,
      'client_version': GetClientVersion(),
      'on_corp': on_corp,
      'last_notified_datetime': last_notified_datetime,
      'uptime': uptime,
      'root_disk_free': root_disk_free,
      'user_disk_free': user_disk_free,
  }
  return client_id


def ClientIdDictToStr(client_id):
  """Returns a passed client_id dict as a string.

  Args:
    client_id: dict client identifer.

  Returns:
    String.  "uuid=<v>|owner=<v>|hostname=<v>|track=<v>" where "<v>" is the
    value. Any values that cannot be obtained default to an empty string.
  """
  out = []
  for key, value in client_id.iteritems():
    if value is None:
      out.append('%s=' % key)
    else:
      out.append('%s=%s' % (key, value))
  return DELIMITER.join(out)


def GetAppleSUSCatalog():
  """Fetches an Apple Software Update Service catalog from the server.

  Args:
    client_id: dict client id.
    token: optional str auth token.
  """
  url = GetPlistValue('SoftwareRepoURL', secure=False)
  try:
    updatecheck.getHTTPfileIfChangedAtomically(
        '%s/applesus/' % url, APPLE_SUS_CATALOG)
    # Update the CatalogURL setting in com.apple.SoftwareUpdate.plist.
    sus_catalog = fpl.readPlist(APPLE_SUS_PLIST)
    sus_catalog['CatalogURL'] = (
        'file://%s' % APPLE_SUS_CATALOG.replace(' ', '%20'))
    fpl.writePlist(sus_catalog, APPLE_SUS_PLIST)
  except updatecheck.CurlDownloadError, e:
    print >>sys.stderr, 'CurlDownloadError getting Apple SUS catalog: ', str(e)


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
    print >>sys.stderr, 'Failure post to report to server: %s', str(e)
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
    rc, stdout, stderr = Exec(cmd)
    if rc != 0:
      raise OSError('Exec %d: %s' % (rc, stderr), rc)
  except OSError, e:
    if raise_exc is True:
      raise
    # gracefully allow failed server requests, but display error.
    print >>sys.stderr, 'Error contacting server: %s', str(e)

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


def GetManagedInstallReport():
  """Returns the ManagedInstallReport.plist plist object."""
  managed_installs_dir = munkicommon.pref('ManagedInstallDir')
  install_report_path = os.path.join(
      managed_installs_dir, 'ManagedInstallReport.plist')
  try:
    install_report = fpl.readPlist(install_report_path)
  except fpl.NSPropertyListSerializationException, e:
    print >>sys.stderr, 'Error reading ', install_report_path, ': ', str(e)
    return {}, install_report_path
  return install_report, install_report_path


def GetRemainingPackagesToInstall():
  """Returns a list of string packages that are remaining to install."""
  install_report, unused_path = GetManagedInstallReport()
  if not install_report:
    return []

  just_installed = install_report.get('InstallResults', [])
  pkgs_to_install_dicts = install_report.get('ItemsToInstall', [])
  pkgs_to_install = []

  for item_dict in pkgs_to_install_dicts:
    pkg = '%s-%s' % (
        item_dict.get('display_name', item_dict.get('name')),
        item_dict.get('version_to_install', ''))
    pkg_report = 'Install of %s: SUCCESSFUL' % pkg
    if pkg_report not in just_installed:
      pkgs_to_install.append(pkg.encode('utf-8'))

  return pkgs_to_install


def ReportInstallsToServerAndLogout(on_corp, logout=False):
  """Reports any installs, updates, uninstalls back to Simian server.

  If no reports of installs/updates/uninstalls exist to report,
  then this function only contacts the server if logout is True.

  Args:
    on_corp: str, on_corp status from GetClientIdentifier.
    logout: bool, default False, whether to logout or not.
  """
  install_report, install_report_path = GetManagedInstallReport()
  if not install_report:
    return

  installs = install_report.get('InstallResults', [])  # includes updates.
  removals = install_report.get('RemovalResults', [])
  problem_installs = install_report.get('ProblemInstalls', [])

  # encode all strings to utf-8 for unicode character support.
  for item_list in [installs, removals]:
    for i in xrange(len(item_list)):
      item_list[i] = unicode(item_list[i]).encode('utf-8')

  # convert dict problems to strings, and encode as utf-8.
  for i in xrange(len(problem_installs)):
    p = problem_installs[i]
    if p.__class__.__name__ == 'NSCFDictionary':
      p = u'%s: %s' % (p.get('name', ''), p.get('note', ''))
    problem_installs[i] = p.encode('utf-8')

  if installs or removals or problem_installs:
    data = {
        'on_corp': on_corp,
        'installs': installs,
        'removals': removals,
        'problem_installs': problem_installs,
    }
    try:
      PostReportToServer('install_report', data, logout=logout, raise_exc=True)
    except ServerRequestError:
      return

    # clear reportable information now that is has been published.
    install_report['InstallResults'] = []
    install_report['RemovalResults'] = []
    install_report['ProblemInstalls'] = []
    fpl.writePlist(install_report, install_report_path)
  else:
    if logout:
      PerformServerRequest(logout=True)