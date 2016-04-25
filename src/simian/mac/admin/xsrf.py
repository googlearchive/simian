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
"""XSRF generator/validator."""

import base64
import hmac
import os
import time

from google.appengine.api import users

from simian import settings

XSRF_DELIMITER = '|#|'
XSRF_VALID_TIME = 3600  # Seconds = 60 minutes


def XsrfTokenGenerate(action, user=None, timestamp=None):
  """Generate an XSRF token."""
  if not user:
    user = users.get_current_user().email()
  if not timestamp:
    timestamp = time.time()
  timestr = str(timestamp)
  try:
    secret = settings.XSRF_SECRET
  except AttributeError:
    secret = os.urandom(16).encode('base64')[:20]
    settings.XSRF_SECRET = secret
  secret = str(secret)  # hmac secrets cannot be unicode.
  h = hmac.new(secret, XSRF_DELIMITER.join([user, action, timestr]))
  return base64.b64encode(''.join([h.digest(), XSRF_DELIMITER, timestr]))


def XsrfTokenValidate(token, action, user=None, timestamp=None, time_=time):
  """Validate an XSRF token."""
  if not token:
    return False
  if not user:
    user = users.get_current_user().email()
  if not timestamp:
    try:
      _, timestr = base64.b64decode(token).split(XSRF_DELIMITER, 1)
      timestamp = float(timestr)
    except (ValueError, TypeError):
      return False

  if timestamp + XSRF_VALID_TIME < time_.time():
    return False
  if token != XsrfTokenGenerate(action, user, timestamp):
    return False
  return True
