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
"""Custom postflight script to run before bulk of Munki executions."""

import logging
import os
import sys

from munkilib import munkicommon

from simian.mac.client import client as mac_client
from simian.mac.client import flight_common

LAST_SUCCESS_FILE = '/Library/Managed Installs/lastsuccess'


def RemoveAuthTokenHeaderFromPlist(plist):
  """Expires auth token and removes cookie header from a plist object.

  Args:
    plist: FoundationPlist.NSCFDictionary object.
  """
  # TODO(user): Port to CFP, so Mountain Lion removes the token as well.
  headers = []
  # Expire the auth token, and preserve all non-Cookie headers that may exist.
  if munkicommon.ADDITIONAL_HTTP_HEADERS_KEY in plist:
    # remove cookie headers from the plist.
    for header in plist[munkicommon.ADDITIONAL_HTTP_HEADERS_KEY]:
      if not header.startswith('Cookie:'):
        headers.append(header)
    if headers:
      plist[munkicommon.ADDITIONAL_HTTP_HEADERS_KEY] = headers
    else:
      # if there are no headers remaining, delete the key entirely.
      del plist[munkicommon.ADDITIONAL_HTTP_HEADERS_KEY]


def NoteLastSuccess(open_=open):
  output_file = open_(LAST_SUCCESS_FILE, 'w')
  output_file.write('Success')


def IsAppInPlace():
  """Determines if MSU application is installed in the right place."""
  return (os.path.isdir('/Applications/Utilities/Managed Software Update.app/')
          or os.path.isdir('/Applications/Managed Software Center.app/'))


def RunPostflight(runtype):
  """Run the full postflight script."""
  # support enterprise/802.1x user-context wifi auth.
  # don't bother to perform postflight and exit OK immediately since there's no
  # network connection.
  if runtype == 'logoutinstall':
    sys.exit(0)

  url = flight_common.GetServerURL()
  client = mac_client.SimianAuthClient(
      flight_common.GetClientIdentifier('auto')['uuid'], hostname=url)
  client.SetAuthToken(flight_common.GetAuth1Token())

  # read SecureConfig.plist.
  plist = munkicommon.SecureManagedInstallsPreferences()

  # Post client_id to server.
  client_id = flight_common.GetClientIdentifier(runtype)
  pkgs_to_install, apple_updates_to_install = (
      flight_common.GetRemainingPackagesToInstall())
  params = {
      'client_id': flight_common.DictToStr(client_id),
      'pkgs_to_install': pkgs_to_install,
      'apple_updates_to_install': apple_updates_to_install,
  }
  client.PostReport('postflight', params)

  # Report installs/etc to server.
  flight_common.UploadAllManagedInstallReports(
      client, client_id.get('on_corp', 'None'))

  # Ensure MSU is installed to /Applications
  if not IsAppInPlace():
    flight_common.RepairClient()

  if not client.LogoutAuthToken():
    logging.error('Logout failed')

  # expire auth token and remove cookie from plist.
  RemoveAuthTokenHeaderFromPlist(plist)

  # Delete the temp dir that munkicommon creates on import.
  munkicommon.cleanUpTmpDir()

  # Mark successful run by writing to last success file.
  NoteLastSuccess()

  logging.debug('Preflight completed successfully.')
