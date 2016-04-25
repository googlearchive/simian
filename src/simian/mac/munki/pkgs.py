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
"""Tools for manipulating OSX packages with Munki."""

import os
import subprocess
from simian.mac.munki import plist


MUNKI_PATH = '/usr/local/munki/'
MAKEPKGINFO = 'makepkginfo'


class Error(Exception):
  """Base Error class."""


class UnsupportedOSError(Error):
  """Error when current OS is unsupported."""


class MunkiInstallError(Error):
  """Error when the system Munki installation is broken."""


class MunkiError(Error):
  """Error when underlying Munki tools return errors."""


class MunkiPackageInfo(object):
  """Class which handles Munki package info."""

  REQUIRED_MUNKI_BINS = [MAKEPKGINFO]

  def __init__(self):
    self.filename = None
    self.plist = None
    self.munki_path = MUNKI_PATH
    self.munki_install_verified = False

  def IsOSX(self):
    """Returns True if the current OS is OS X, False if not."""
    return os.uname()[0] == 'Darwin'

  def _GetMunkiPath(self, filename):
    """Given a filename, return a full path including leading Munki path.

    Args:
      filename: str, like 'munkitool'
    Returns:
      str, like '/usr/local/munki/munkitool'
    """
    return os.path.join(self.munki_path, filename)

  def VerifyMunkiInstall(self):
    """Verify that Munki is installed and accessible on this system.

    Raises:
      MunkiInstallError: if a problem is detected
    """
    if self.munki_install_verified:
      return

    for k in os.environ:
      if k.startswith('PKGS_MUNKI_'):
        return

    if not self.IsOSX():
      raise MunkiInstallError('Required Munki utilities only run on OS X')

    if not os.path.isdir(self.munki_path):
      raise MunkiInstallError(
          '%s does not exist or is not a directory' % self.munki_path)

    for f in self.REQUIRED_MUNKI_BINS:
      if not os.path.isfile(self._GetMunkiPath(f)):
        raise MunkiInstallError(
            '%s/%s does not exist or is not a file' % self._GetMunkiPath(f))

    self.munki_install_verified = True

  def CreateFromPackage(self, filename, description, display_name, catalogs):
    """Create package info from a live package stored at filename.

    Args:
      filename: str
      description: str, like "Security update for Foo Software"
      display_name: str, like "Munki Client"
      catalogs: list of str catalog names.
    """
    self.VerifyMunkiInstall()

    args = [self._GetMunkiPath(MAKEPKGINFO), filename]
    args.append('--description=%s' % description)
    if display_name:
      args.append('--displayname=%s' % display_name)
    for catalog in catalogs:
      args.append('--catalog=%s' % catalog)

    if 'PKGS_MUNKI_MAKEPKGINFO' in os.environ:
      args[0] = os.environ['PKGS_MUNKI_MAKEPKGINFO']

    try:
      p = subprocess.Popen(
          args,
          stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
          close_fds=True,
          shell=False)
    except OSError, e:
      raise MunkiInstallError('Cannot execute %s: %s' % (' '.join(args), e))

    (stdout, stderr) = p.communicate(None)
    status = p.poll()

    if status == 0 and stdout and not stderr:
      self.filename = filename
    else:
      raise MunkiError(
          'makepkginfo: exit status %d, stderr=%s' % (status, stderr))

    self.plist = plist.MunkiPackageInfoPlist(stdout)
    try:
      self.plist.Parse()
    except plist.Error, e:
      raise Error(str(e))

  def GetPlist(self):
    """Returns the package info as plist.MunkiPackageInfoPlist object."""
    return self.plist
