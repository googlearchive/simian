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

  def UploadPackage(self):
    """Uploads a package and pkginfo plist to Simian."""
    print 'Uploading package to Simian....'
    filename = self.config['package']
    description = self.config['description']
    display_name = self.config['display_name']

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
    catalogs = self.config['catalogs'] or 'unstable'
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
    install_types = self.config['install_types'] or 'managed_installs'
    install_types = install_types.replace(' ', '')  # replace any whitespace
    install_types = install_types.split(',')  # parse install types into list
    for install_type in install_types:
      if install_type not in common.INSTALL_TYPES:
        raise CliError(
            'install_type "%s" is not in supported types: %s' % (
                install_type, common.INSTALL_TYPES))

    if not os.path.isfile(filename):
      raise CliError('File not found: %s' % filename)

    opts = {}
    if self.config['edit_pkginfo'] is not None:
      opts['pkginfo_hook'] = self.PackageInfoEditHook
    if self.config['forced_install'] is not None:
      opts['forced_install'] = True

    response, filename, name, catalogs, manifests, size_kbytes, sha256_hash = (
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, **opts))

    print 'Package successfully uploaded!'
    print 'Blobstore key: %s' % response
    print 'Catalogs: %s' % catalogs
    print 'Manifests: %s' % catalogs
    print 'Install Types: %s' % install_types
    print 'Package name: %s' % name
    print 'File name: %s' % filename
    print 'File size: %.2f MB' % (size_kbytes / 1024.0)
    print 'File hash: %s' % sha256_hash

  def EditPackageInfo(self):
    """Edit a package's pkginfo."""
    (sha_hash, pkginfo_xml) = self.client.GetPackageInfo(
        self.config['package'], get_hash=True)
    pkginfo = plist.MunkiPackageInfoPlist(pkginfo_xml)
    pkginfo.Parse()
    new_pkginfo = self.PackageInfoEditHook(pkginfo)
    if new_pkginfo:
      if new_pkginfo is not True:
        # the packageinfo is valid, and it has been changed.
        logging.debug('Putting new pkginfo, refering to hash %s', sha_hash)
        self.client.PutPackageInfo(
            self.config['package'], new_pkginfo.GetXml(), got_hash=sha_hash)
        print 'Package info successfully updated.'
      else:
        logging.debug('No change to pkginfo')
    else:
      logging.debug('Pkginfo invalid, aborting.')
