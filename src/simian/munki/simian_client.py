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
"""Wrapper for Simian preflight and postflight functionality."""

import getopt
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


ACTIONS = ['preflight', 'postflight', 'report_broken_client', 'version']


def PrintOptions():
  print 'One of the following actions is required: '
  print '  ', ', '.join(ACTIONS)


def main(args):
  opts, args = getopt.gnu_getopt(args, '', ['debug', 'server='])

  action = args[0] if args else None
  if action not in ACTIONS:
    PrintOptions()
    return 1

  logging.getLogger().setLevel(logging.WARNING)
  server_url = None

  for option, value in opts:
    if option == '--debug':
      logging.getLogger().setLevel(logging.DEBUG)
      # override logging.exception to print helpful tracebacks.
      def NewLoggingException(msg, *args):
        logging.debug(msg, exc_info=sys.exc_info(), *args)
      logging.exception = NewLoggingException
    elif option == '--server':
      server_url = value

  # munki passes a "runtype" to preflight/postflight; i.e. auto, manual, etc.
  runtype = args[1] if len(args) > 1 else 'custom'

  if action == 'preflight':
    preflight.RunPreflight(runtype, server_url=server_url)
  elif action == 'postflight':
    postflight.RunPostflight(runtype)
  elif action == 'report_broken_client':
    report_broken_client.main()
  elif action == 'version':
    print version.VERSION
  else:
    PrintOptions()
    return 1
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
