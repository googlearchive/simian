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


# Magic value which can be supplied by the user on the CLI to mean that this
# list value has no entities, e.g. the resulting value internally should
# become [].
LIST_EMPTY = 'none'


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

  def PackageInfoTemplateHook(self, input_pkginfo, open_=open):
    """Allow a template to supply values into the pkginfo.

    The template is loaded. Its values are overlaid onto a new pkginfo
    instance with values copied from the one that is supplied as
    input_pkginfo. Note this means callers to this method will not have
    their input_pkginfo modified, rather a new pkginfo is received as output
    if any values changed.

    Args:
      input_pkginfo: plist.MunkiPackageInfoPlist, input pkginfo to use as base
        values
    Returns:
      a different plist.MunkiPackageInfoPlist instance with potentially new
      values populated
    Raises:
      CliError: an error occurs reading the template
    """
    pkginfo = input_pkginfo.copy()
    try:
      plist_xml = open_(self.config['template_pkginfo'], 'r').read()
      template = plist.ApplePlist(plist_xml)
      template.Parse()
    except IOError:
      raise CliError('I/O error %s' % self.config['template_pkginfo'])
    except plist.Error, e:
      raise CliError(
          'Error parsing %s: %s' % (
              self.config['template_pkginfo'],
              str(e)))

    if type(template.GetContents()) is not dict:
      raise CliError('Template should contain a dictionary at top level')

    logging.debug('Overlaying pkginfo with template')

    changed = False

    for k in template:
      if k not in pkginfo or pkginfo[k] != template[k]:
        changed = True
        pkginfo[k] = template[k]
        logging.debug('Pkginfo value %s changed by template', k)

    logging.debug('Pkginfo changed as result of template: %s', changed)

    if changed:
      try:
        pkginfo.Validate()
      except plist.Error, e:
        logging.exception('Template resulted in broken pkginfo: %s' % str(e))
        return False
      return pkginfo
    else:
      return True

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
        pkginfo = plist.MunkiPackageInfoPlist(fd.read())
        fd.close()
        pkginfo.Parse()
        break
      except IOError:
        edit = False
      except plist.Error, e:
        print 'Error parsing plist: %s' % str(e)
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
        str filepath, str description, str display_name, str pkginfo_name,
        list manifests, list catalogs, list install_types,
        bool unattended_install, bool unattended_uninstall
      )
    Raises:
      CliError: if a config parameter is invalid
    """
    # Parse manifests, and verify each is valid.
    manifests = self.config['manifests']
    if manifests is not None:
      if manifests.lower() == LIST_EMPTY:
        manifests = []
      else:
        manifests = manifests.replace(' ', '')  # replace any whitespace
        manifests = manifests.split(',')  # parse manifest names into list
        for manifest in manifests:
          if manifest not in common.TRACKS:
            raise CliError(
                'manifest "%s" is not in support manifests: %s' % (
                    manifest, common.TRACKS))

    # Parse catalogs, and verify each is valid.
    if defaults:
      if self.config['catalogs'] is None:
        catalogs = 'unstable'
      else:
        catalogs = self.config['catalogs']
    else:
      catalogs = self.config['catalogs']

    if catalogs is not None:
      if catalogs.lower() == LIST_EMPTY:
        catalogs = []
      else:
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
        if manifest not in common.TRACKS:
          raise CliError(
              'manifest value %s not valid' % manifest)

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
      if (common.MANAGED_INSTALLS in install_types and
          common.MANAGED_UPDATES in install_types):
        raise CliError(
            'install_types must not contain both %s and %s.' % (
                common.MANAGED_INSTALLS, common.MANAGED_UPDATES))

    filepath = self.config['package']
    if not filepath:
      raise CliError('package is required')

    description = self.config['description']
    display_name = self.config['display_name']
    pkginfo_name = self.config['name']

    if defaults:
      # default, off
      unattended_install = self.config['unattended_install'] is not None
      unattended_uninstall = self.config['unattended_uninstall'] is not None
    else:
      if self.config['unattended_install'] is None:
        unattended_install = None
      else:
        unattended_install = self.config['unattended_install'] in ['', True]

      if self.config['unattended_uninstall'] is None:
        unattended_uninstall = None
      else:
        unattended_uninstall = self.config['unattended_uninstall'] in ['', True]

    return (
      filepath, description, display_name, pkginfo_name,
      manifests, catalogs, install_types, unattended_install,
      unattended_uninstall
    )

  # TODO(user): The pkginfo_hooks code in EditPackageInfo needs to be
  # refactored into a generic solution that both UploadPackage and
  # EditPackageInfo can use. That private function should probably be
  # right here.

  def UploadPackage(self):
    """Uploads a package and pkginfo plist to Simian."""

    print 'Uploading package ...'

    (filename, description, display_name, pkginfo_name,
    manifests, catalogs, install_types,
    unattended_install, unattended_uninstall) = self.ValidatePackageConfig()

    if not os.path.exists(filename):
      raise CliError('Package file does not exist: %s' % filename)
    elif os.path.isdir(filename):
      raise CliError('Package must be a file, not a pkg/mpkg bundle dir')
    elif not os.path.isfile(filename):
      raise CliError('Package must be a file')

    opts = {}
    opts['pkginfo_hooks'] = []
    if self.config['template_pkginfo'] is not None:
      opts['pkginfo_hooks'].append(self.PackageInfoTemplateHook)
    if self.config['edit_pkginfo'] is not None:
      opts['pkginfo_hooks'].append(self.PackageInfoEditHook)
    if unattended_install:
      opts['unattended_install'] = True
    if unattended_uninstall:
      opts['unattended_uninstall'] = True
    if pkginfo_name:
      opts['pkginfo_name'] = pkginfo_name

    (response, filename, name,
    catalogs, manifests, size_kbytes, sha256_hash) = (
        self.client.UploadMunkiPackage(
            filename, description, display_name, catalogs, manifests,
            install_types, **opts))

    print 'Package upload successful!'
    print 'Blobstore key: %s' % response
    print 'Catalogs: %s' % catalogs
    print 'Manifests: %s' % manifests
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
    (filepath, description, display_name, pkginfo_name,
    manifests, catalogs, install_types,
    unattended_install, unattended_uninstall) = (
        self.ValidatePackageConfig(defaults=False))

    print 'Editing package info ...'

    filename = os.path.basename(filepath)

    (sha256_hash, pkginfo_xml) = self.client.GetPackageInfo(
        filename, get_hash=True)

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
    if pkginfo_name is not None:
      pkginfo['name'] = pkginfo_name
      changes.append('Pkginfo name: %s' % pkginfo_name)
    if unattended_install is not None:
      pkginfo.SetUnattendedInstall(unattended_install)
      changes.append('Unattended install: %s' % unattended_install)
    if unattended_uninstall is not None:
      pkginfo.SetUnattendedUninstall(unattended_uninstall)
      changes.append('Unattended uninstall: %s' % unattended_uninstall)
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

    edit_hooks = []

    if self.config['template_pkginfo'] is not None:
      edit_hooks.append(self.PackageInfoTemplateHook)
    if self.config['edit_pkginfo'] is not None:
      edit_hooks.append(self.PackageInfoEditHook)

    # TODO(user): Refactor so that this code block and
    # mac.client.UploadMunkiPackage share the same pkginfo_hooks iteration
    # code.
    for edit_hook in edit_hooks:
      if edit_hook is not None:
        new_pkginfo = edit_hook(pkginfo)
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

    # verify catalogs / manifests relationship
    if manifests is not None:
      intended_catalogs = (kwargs.get('catalogs', None) or
          pkginfo.GetContents().get('catalogs', []))
      for manifest in manifests:
        if manifest not in intended_catalogs:
          raise CliError('Manifest %s not in catalogs' % manifest)

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

    self.client.PutPackageInfo(filename, new_xml, **kwargs)

    print 'Package info update successful!'
    print 'Package name: %s' % filename
    print '\n'.join(changes)