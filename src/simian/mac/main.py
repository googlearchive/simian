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




import logging
import os
import sys

import appengine_config

# catch fatal datastore errors and provide a friendly but minimal message.
CATCH_DATASTORE_FATAL = True


def BasicExceptionPrint(exc_type, exc_value, exc_traceback):
  """Print a user-friendly message and log an offending exception.

  Args:
    exc_type, exc_value, exc_traceback:
      per sys.exc_type, exc_value, exc_traceback documentation
  """
  print 'Content-Type: text/plain'
  print
  print 'Simian is currently experiencing problems that may be'
  print 'specific to Simian.  They also may be related to a general'
  print 'outage in the App Engine infrastructure.'
  print
  print 'Connectivity to the site will be restored ASAP.'

  try:
    import logging
    import traceback
    log_exception = True
  except ImportError:
    log_exception = False

  if log_exception:
    logging.error('Exception occured\nType: %s\nValue: %s\nTraceback:\n%s' %
        (exc_type, exc_value, '\n'.join(traceback.format_tb(exc_traceback))))
    print 'This error has been logged.'
  else:
    print 'This error has not been logged.'


def main():
  from google.appengine.api import users
  from simian.mac import urls

  main_method = urls.main

  if CATCH_DATASTORE_FATAL:
    import google.appengine
    try:
      main_method()
    except (
        google.appengine.api.datastore_errors.Timeout,
        google.appengine.api.datastore_errors.InternalError,
        google.appengine.runtime.apiproxy_errors.CapabilityDisabledError):
      BasicExceptionPrint(*sys.exc_info())
  else:
    main_method()

if __name__ == '__main__':
  main()