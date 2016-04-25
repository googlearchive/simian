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
"""Custom script to report broken installs to Simian.

In case machines have broken Python installs, this script cannot contain any
Python imports requiring ObjC bindings.  This means we cannot use
flight_import, munkicommon, etc.
"""

import optparse

from simian.mac.client import client
from simian.mac.client import flight_common


def main():
  optparser = optparse.OptionParser()
  optparser.add_option(
      '-r', '--reason', dest='reason', default='Unknown',
      help='Reason for brokenness.')
  optparser.add_option(
      '-d', '--detail-file', dest='detail_file',
      help='File with error details.')
  options, _ = optparser.parse_args()

  detail_parts = []

  if options.detail_file:
    try:
      detail_parts.append(
          'Failure detail:\n%s' % open(options.detail_file, 'r').read())
    except IOError as e:
      detail_parts.append(
          'Could not read detail file %r:\n%s' % (options.detail_file, e))


  return_code, stdout, stderr = flight_common.Exec(
      ['facter', '-p'], timeout=60, waitfor=0.5)
  facter_parts = [
      'Facter Return Code: %s' % return_code,
      'Facter StdOut:\n%s' % stdout,
  ]
  if stderr:
    facter_parts.append('Facter StdErr:\n%s' % stderr)
  detail_parts.append('\n\n'.join(facter_parts))

  details = ('\n\n' + ('*' * 60) + '\n\n').join(
      [part.strip() for part in detail_parts])
  params = {'details': details, 'reason': options.reason}

  url = flight_common.GetServerURL()
  c = client.SimianAuthClient(hostname=url)
  c.GetAuthToken()
  c.PostReport('broken_client', params)
  print 'Reported broken client to server.'


if __name__ == '__main__':
  main()
