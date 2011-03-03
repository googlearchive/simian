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

"""Mac CLI for Simian client"""




import getopt
import logging
import os
import platform
import sys
import tempfile
from simian.client import cli
from simian.mac import common
from simian.mac.client import client
from simian.mac.munki import plist


class Error(Exception):
  """Base Error class."""


class CliError(Error, cli.CliError):
  """Cli error."""


class SimianCliClient(cli.SimianCliClient):
  """Simian CLI client class."""

  NAME = 'Simian'

  def GetSimianClientInstance(self, *args, **kwargs):
    """Returns an instance of the Simian client to use within this CLI."""
    return client.SimianClient(*args, **kwargs)

  def PackageInfoEditHook(self, pkginfo):
    """Allow an interactive user to edit package info before uploading.

    Args:
      pkginfo: plist.MunkiPackageInfoPlist
    Returns:
      True if the package info is acceptable and no changes are necessary
      False if the user has given up editing the package info and wishes
          to abort the process
      a plist.MunkiPackageInfoPlist if a new package info is being returned
    """
    orig_pkginfo = pkginfo
    (fd, filename) = tempfile.mkstemp('.plist')
    os.write(fd, pkginfo.GetXml())
    os.close(fd)

    edit = True
    while edit:
      self._RunEditor(filename)
      try:
        fd = open(filename, 'r')
        pkginfo = plist.MunkiPackageInfoPlist(fd.read(10240))
        fd.close()
        pkginfo.Parse()
        break
      except IOError:
        edit = False
      except plist.Error:
        yn = raw_input('Resulting plist contains errors. Re-edit? [y/n] ')
        edit = yn.upper() in ['YES', 'Y']

    try:
      os.unlink(filename)
    except OSError:
      pass

    if edit:
      if pkginfo.GetContents() != orig_pkginfo.GetContents():
        return pkginfo
      else:
        return True
    else:
      return False

  def ValidatePackageConfig(self, defaults=True):
    """Validate package config parameters.

    Reads self.config dict.

    Args:
      defaults: bool, default True, whether to provide default values
        for catalogs and install_types value if no values are provided.
    Returns:
      tuple of (
        str filename, str description, str display_name,
        list manifests, list catalogs, list install_types, bool forced_install
      )
    Raises:
      CliError: if a config parameter is invalid
    """
    # Parse manifests, and verify each is valid.
    manifests = self.config['manifests']
    if manifests:
      manifests = manifests.replace(' ', '')  # replace any whitespace
      manifests = manifests.split(',')  # parse manifest names into list
      for manifest in manifests:
        if manifest not in common.TRACKS:
          raise CliError(
              'manifest "%s" is not in support manifests: %s' % (
                  manifest, common.TRACKS))

    # Parse catalogs, and verify each is valid.
    if defaults:
      catalogs = self.config['catalogs'] or 'unstable'
    else:
      catalogs = self.config['catalogs']

    if catalogs:
      catalogs = catalogs.replace(' ', '')  # replace any whitespace
      catalogs = catalogs.split(',')  # parse catalog names into list
      for catalog in catalogs:
        if catalog not in common.TRACKS:
          raise CliError(
              'catalog "%s" is not in support catalogs: %s' % (
                  catalog, common.TRACKS))

    # Verify all manifests have associated catalogs.
    if manifests:
      for manifest in manifests:
        if manifest not in catalogs:
          raise CliError(
              'manifest does not have matching catalog: %s' % manifest)

    # Parse install types, and verify each is valid.
    if defaults:
      install_types = self.config['install_types'] or 'managed_installs'
    else:
      install_types = self.config['install_types']

    if install_types:
      install_types = install_types.replace(' ', '')  # replace any whitespace
      install_types = install_types.split(',')  # parse install types into list
      for install_type in install_types:
        if install_type not in common.INSTALL_TYPES:
          raise CliError(
              'install_type "%s" is not in supported types: %s' % (
                  install_type, common.INSTALL_TYPES))

    filename = self.config['package']
    description = self.config['description']
    display_name = self.config['display_name']

    if defaults:
      # default, off
      forced_install = self.config['forced_install'] is not None
    else:
      if self.config['forced_install'] is None:
        forced_install = None
      else:
        forced_install = self.config['forced_install'] in ['', True]

    return (
      filename, description, display_name,
      manifests, catalogs, install_types, forced_install
    )

  def UploadPackage(self):
    """Uploads a package and pkginfo plist to Simian."""

    print 'Uploading package ...'

    (filename, description, display_name,
    manifests, catalogs, install_types,
    forced_install) = self.ValidatePackageConfig()

    if not os.path.isfile(filename):
      raise CliError('File not found: %s' % filename)

    opts = {}
    if self.config['edit_pkginfo'] is not None:
      opts['pkginfo_hook'] = self.PackageInfoEditHook
    if forced_install:
      opts['forced_install'] = True

    (response, filename, name,
    catalogs, manifests, size_kbytes, sha256_hash) = (
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, **opts))

    print 'Package upload successful!'
    print 'Blobstore key: %s' % response
    print 'Catalogs: %s' % catalogs
    print 'Manifests: %s' % catalogs
    print 'Install Types: %s' % install_types
    print 'Package name: %s' % name
    print 'File name: %s' % filename
    print 'File size: %.2f MB' % (size_kbytes / 1024.0)
    print 'File sha256 hash: %s' % sha256_hash

  def EditPackageInfo(self):
    """Edit package info on a package already on Simian.

    Raises:
      CliError: if package info is malformed
    """
    (name, description, display_name,
    manifests, catalogs, install_types,
    forced_install) = self.ValidatePackageConfig(defaults=False)

    print 'Editing package info ...'

    (sha256_hash, pkginfo_xml) = self.client.GetPackageInfo(
        name, get_hash=True)

    pkginfo = plist.MunkiPackageInfoPlist(pkginfo_xml)
    pkginfo.Parse()

    kwargs = {}
    changes = []

    # these values would be None if the user did not specify a value.
    # note the change detection is a little weak, if we overwrite any
    # value, even with the same values, we count it as a change.
    if description is not None:
      pkginfo.SetDescription(description)
      changes.append('Description: %s' % description)
    if display_name is not None:
      pkginfo.SetDisplayName(display_name)
      changes.append('Display name: %s' % display_name)
    if forced_install is not None:
      pkginfo.SetForcedInstall(forced_install)
      changes.append('Forced install: %s' % forced_install)
    if catalogs is not None:
      pkginfo.SetCatalogs(catalogs)
      kwargs['catalogs'] = catalogs
      changes.append('Catalogs: %s' % catalogs)
    if manifests is not None:
      kwargs['manifests'] = manifests
      changes.append('Manifests: %s' % manifests)
    if install_types is not None:
      kwargs['install_types'] = install_types
      changes.append('Install types: %s' % install_types)

    if self.config['edit_pkginfo'] is not None:
      new_pkginfo = self.PackageInfoEditHook(pkginfo)
      if new_pkginfo:
        if new_pkginfo is not True:
          pkginfo = new_pkginfo  # changed and valid
          pkginfo.SetChanged()
          # populate catalogs value back into our properties
          catalogs = pkginfo.GetContents().get('catalogs', [])
          kwargs['catalogs'] = catalogs
        else:
          pass # no change at all
      else:
        raise CliError('Invalid package info')  # changed but invalid now

    if not kwargs and not pkginfo.HasChanged():
      print 'Package info unchanged.'
      return

    # Parse pkginfo.GetXml() to ensure it's still valid before uploading.
    new_xml = pkginfo.GetXml()
    try:
      tmp_pkginfo = plist.MunkiPackageInfoPlist(new_xml)
      tmp_pkginfo.Parse()
    except plist.Error, e:
      raise CliError('Invalid package info: %s', str(e))

    print 'Updating package info ...'
    kwargs['got_hash'] = sha256_hash

    # The underlying API call that PutPackageInfo() makes only modifies
    # arguments that are supplied.  Therefore this code does not need to
    # obtain, e.g.  the old manifests value and re-PUT it to avoid losing
    # the value while intending to changing catalogs value.

    self.client.PutPackageInfo(name, new_xml, **kwargs)

    print 'Package info update successful!'
    print 'Package name: %s' % name
    print '\n'.join(changes)