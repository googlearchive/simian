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

"""Module containing classes to connect to Simian as a Mac client."""





import logging
import os
import os.path
import platform
import subprocess
from simian.client import client
from simian.mac.munki import pkgs
from simian.mac.munki import plist


MUNKI_CONFIG_PLIST = '/Library/Preferences/ManagedInstalls.plist'


class Error(Exception):
  """Base Error class."""


def GetMunkiConfigParam(param, munki_config_plist=MUNKI_CONFIG_PLIST):
  """Get Munki configuration.

  Args:
    param: str, key to return, e.g. 'SoftwareRepoURL'
    munki_config_plist: str, optional, filename to read from
  Returns:
    str, SoftwareRepoURL value
    or None if the value cannot be determined
  """
  if platform.uname()[0] == 'Darwin':
    # I'm sorry :( blame binary plists.
    domain = munki_config_plist.rsplit('.', 1)[0]
    argv = ['/usr/bin/defaults', 'read', domain, param]
    try:
      p = subprocess.Popen(
          argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      (stdout, stderr) = p.communicate()
      rc = p.wait()
    except OSError:
      return

    if rc != 0 or stderr:
      logging.debug('defaults read returned %s: %s', rc, stderr)
      return

    if stdout:
      stdout = stdout.strip()

    return stdout
  else:
    try:
      f = open(munki_config_plist, 'r')
      s = f.read(10240)
      f.close()
      mpi = plist.MunkiPlist(s)
      pl = mpi.GetXml()
    except (IOError, plist.Error), e:
      logging.debug('Error reading %s: %s', munki_config_plist, str(e))
      return
    return pl.get(param, None)


def GetMunkiSoftwareRepoURL():
  """Get SoftwareRepoURL parameter from Munki config."""
  return GetMunkiConfigParam('SoftwareRepoURL')


class BaseSimianClient(object):
  """Base client features in all Mac clients."""

  def _LoadMunkiConfiguration(self):
    """Load Munki configuration to assist in configuring this Simian client."""
    self.munki_config_plist = MUNKI_CONFIG_PLIST
    url = GetMunkiSoftwareRepoURL()
    if url:
      if self.IsDefaultHostClient():
        self._LoadHost(url)

  def GetSystemRootCACertChain(self):
    """Load certificate chain from system.

    Returns:
      str, all X509 root ca certs, or '' if none can be found
    """
    certs = client.SimianClient.GetSystemRootCACertChain(self)
    if certs != '':
      return certs

    try:
      argv = [
        '/usr/bin/security',
        'find-certificate', '-a',
        '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'
      ]
      logging.debug('GetSystemRootCACertChain: Executing %s', argv)
      p = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      (stdout, stderr) = p.communicate()
      rc = p.wait()
    except OSError:
      return ''

    if rc == 0:
      logging.debug(
          'GetSystemRootCACertChain: returning %d bytes', len(stdout))
      return stdout
    else:
      return ''


class SimianClient(BaseSimianClient, client.SimianClient):
  """Client to connect to the Simian server as a Mac client."""

  def __init__(self, hostname=None, port=None):
    super(SimianClient, self).__init__(hostname, port)
    self._LoadMunkiConfiguration()

  def _LoadPackageInfo(self, filename, description, display_name, catalogs):
    """Load package info from a file and return its package info.

    Args:
      filename: str, like /tmp/foo.dmg
      description: str, like "Security update for Foo Software"
      display_name: str, like "Munki Client"
      catalogs: list of str catalogs.
    Returns:
      plist.MunkiPackageInfoPlist object.
    Raises:
      client.SimianClientError: there was an error creating the pkginfo plist.
    """
    p = pkgs.MunkiPackageInfo()
    try:
      p.CreateFromPackage(filename, description, display_name, catalogs)
    except pkgs.Error, e:
      raise client.SimianClientError(str(e))
    return p.GetPlist()

  def _IsPackageUploadNecessary(self, filename, upload_pkginfo):
    """Returns True if the package file should be uploaded.

    This method helps the client decide whether to upload the entire package
    and package info, or just new package info.  It compares the sha256 hash
    of the existing package on the server with the one of the package file
    which would potentially be uploaded.  If the existing package info is
    not obtainable or not parseable the hash value cannot be compared, so
    True is returned to force an upload.

    Args:
      filename: str, package filename
      upload_pkginfo: str, new pkginfo to upload.
    Returns:
      True if the package file and package info should be uploaded
      False if the package file is same, so just upload package info
    """
    try:
      cur_pkginfo = self.GetPackageInfo(filename)
    except client.SimianServerError:
      return True

    pkginfo_plist = plist.MunkiPackageInfoPlist(cur_pkginfo)

    try:
      pkginfo_plist.Parse()
    except plist.PlistError:
      return True

    pkginfo = pkginfo_plist.GetContents()

    upload_pkginfo = plist.MunkiPackageInfoPlist(upload_pkginfo)
    upload_pkginfo.Parse()

    if 'installer_item_hash' in pkginfo:
      cur_sha256_hash = pkginfo['installer_item_hash']
    elif 'uninstaller_item_hash' in pkginfo:
      cur_sha256_hash = pkginfo['uninstaller_item_hash']
    else:
      cur_sha256_hash = None

    upload_pkginfo_dict = upload_pkginfo.GetContents()
    if 'installer_item_size' in upload_pkginfo_dict:
      new_sha256_hash = upload_pkginfo_dict['installer_item_hash']
    else:
      new_sha256_hash = upload_pkginfo_dict['uninstaller_item_hash']

    return cur_sha256_hash != new_sha256_hash

  def UploadMunkiPackage(
      self, filename, description, display_name, catalogs, manifests,
      install_types, forced_install=False, pkginfo_hook=None):
    """Uploads a Munki PackageInfo plist along with a Package.

    Args:
      filename: str file name to upload.
      description: str description.
      display_name: str human readable display name.
      catalogs: list of str catalog names.
      manifests: list of str manifest names.
      install_types: list of str install types.
      forced_install: bool, if True inject "forced_install" bool to plist XML.
      pkginfo_hook: optional, function to call with package info after
              generated
    Returns:
      Tuple. (Str response body from upload, filename, name of the package,
              list of manifests, file size in kilobytes, SHA-256 hash of file)
    """
    file_path = filename
    filename = os.path.basename(filename)  # filename should be name only

    pkginfo = self._LoadPackageInfo(
        file_path, description, display_name, catalogs)

    if forced_install:
      pkginfo['forced_install'] = True

    if pkginfo_hook is not None:
      while 1:
        output = pkginfo_hook(pkginfo)
        if output is True:
          break
        elif output is False:
          raise client.SimianClientError('Aborting upload by request.')

        try:
          output.Parse()
          pkginfo = output
          break
        except plist.Error:
          pass

    response, unused_filename, catalogs, manifests = self.UploadPackage(
        filename, description, display_name, catalogs, manifests, install_types,
        pkginfo.GetXml())

    name = pkginfo.GetPackageName()

    if 'installer_item_size' in pkginfo.GetContents():
      sha256_hash = pkginfo.GetContents()['installer_item_hash']
      size_kbytes = pkginfo.GetContents()['installer_item_size']
    else:
      sha256_hash = pkginfo.GetContents()['uninstaller_item_hash']
      size_kbytes = pkginfo.GetContents()['uninstaller_item_size']

    return (response, filename, name, catalogs, manifests, size_kbytes,
            sha256_hash)


class SimianAuthClient(BaseSimianClient, client.SimianAuthClient):
  """Client perform authentication steps with Simian server."""

  def __init__(self, hostname=None, port=None):
    super(SimianAuthClient, self).__init__(hostname, port)
    self._LoadMunkiConfiguration()

  def _GetPuppetSslDetails(self, cert_fname=None, interactive_user=False):
    """Get Puppet SSL details.

    Args:
      cert_fname: str, optiona, certificate filename.
      interactive_user: bool, optional, default False,
        True if the client user an interactive user who can be prompted
        for auth.
    Returns:
      dict = {
          'cert': str, X509 format client certificate in PEM format,
          'ca_cert': str, X509 format CA certificate in PEM format,
          'priv_key': str, X509 format private key in PEM format,
          'cn': str, commonName of this client's certificate
      }
      or {} if the details cannot be read.
    """
    logging.debug('SimianAuthClient._GetPuppetSslDetails')
    if not cert_fname:
      facts = self.GetFacter()
      cert_name = facts.get('certname', None)
      logging.debug('Certname from facter: "%s"', cert_name)
      if not cert_name:
        logging.debug('facter broken; retrieve certname from machineinfo plist')
        info_domain = '/Library/Preferences/com.google.corp.machineinfo'
        cert_name, unused_stderr = self._SudoExec(
            ['/usr/bin/defaults', 'read', info_domain, 'MachineUUID'])
        logging.debug('Certname from machineinfo plist: %s', cert_name)
        cert_name = cert_name.lower()
      cert_fname = '%s.pem' % cert_name
    return super(SimianAuthClient, self)._GetPuppetSslDetails(
        cert_fname=cert_fname, interactive_user=interactive_user)