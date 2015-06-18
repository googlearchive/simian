#!/usr/bin/env python
#
# Copyright 2015 Google Inc. All Rights Reserved.
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
"""Wrapper for Simian preflight and postflight functionality."""

import logging
import sys


# TODO(user): This import hack is ugly; make it more elegant, not tied to 2.6.
import os
sys.path.append('/usr/local/munki')
PYTHON_VERSION = '%s.%s' % (sys.version_info[0], sys.version_info[1])
PYTHON_LIB_ROOT = (
    '/System/Library/Frameworks/Python.framework/Versions/%s/Extras/lib/python/' % PYTHON_VERSION)
sys.path.append(PYTHON_LIB_ROOT)
for directory in os.listdir(PYTHON_LIB_ROOT):
  sys.path.append(PYTHON_LIB_ROOT + directory)

from simian.mac.client import postflight
from simian.mac.client import preflight
from simian.mac.client import report_broken_client
from simian.mac.client import version


# TODO(user): use an option parser and turn this into a --debug flag.
DEBUG = False


def main(args):
  if DEBUG:
    logging.getLogger().setLevel(logging.DEBUG)
  else:
    logging.getLogger().setLevel(logging.WARN)

  server_url = None
  if len(args) > 3:
    server_url = args[3]
  if len(args) > 2:
    runtype = args[2]
  else:
    runtype = 'custom'

  if len(args) == 1:
    logging.error('Syntax is: flight_common flight_type')
  elif args[1] == 'preflight':
    preflight.RunPreflight(runtype, server_url=server_url)
  elif args[1] == 'postflight':
    postflight.RunPostflight(runtype)
  elif args[1] == 'report_broken_client':
    report_broken_client.main()
  elif args[1] == 'version':
    print version.Version(args)
  else:
    logging.error('Unknown flight type %s', args[1])


if __name__ == '__main__':
  main(sys.argv)
