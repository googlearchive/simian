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
"""Module containing classes to connect to Simian as a Mac client."""


import logging
import os
import os.path
import subprocess
from simian.client import client
from simian.mac.common import hw

MUNKI_CONFIG_PLIST = '/Library/Preferences/ManagedInstalls.plist'


class Error(Exception):
  """Base Error class."""


class BaseSimianClient(object):
  """Base client features in all Mac clients."""

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

  def _GetSystemProfile(self):
    """Get hardware profile.

    Returns:
      dict from hw.SystemProfile.GetProfile
    Raises:
      hw.SystemProfilerError: error fetching and parsing System Profiler output.
    """
    sp = hw.SystemProfile(include_only=['network', 'system'])
    profile = sp.GetProfile()
    return profile


class SimianAuthClient(BaseSimianClient, client.SimianAuthClient):
  """Client perform authentication steps with Simian server."""

  def __init__(self, uuid, **kwargs):
    self.uuid = uuid
    client.SimianAuthClient.__init__(self, root_ok=True, **kwargs)

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
      try:
        facts = self.GetFacter()
      except client.FacterError:
        # don't give up, facter fails from time to time.
        facts = {}
      cert_name = facts.get('certname', None)
      logging.debug('Certname from facter: "%s"', cert_name)
      if not cert_name:
        logging.warning('Certname was not found in facter!')
      cert_fname = '%s.pem' % cert_name
    return super(SimianAuthClient, self)._GetPuppetSslDetails(
        cert_fname=cert_fname, interactive_user=interactive_user)
