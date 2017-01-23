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
"""Bridge to support tlslite 0.4.* and 0.3.8."""

import array
import logging
import os
import sys

# pylint: disable=unused-import,g-import-not-at-top
try:
  from tlslite.X509 import X509
  _RETURN_ARRAY = True
except ImportError:
  # tlslite 0.4.0+
  # __init__ in tlslite imports all avaliable api.
  # part of it relies on fcntl which is not avaliable on appengine.
  # we don't use this api, so safely stub out fcntl for appengine
  _RETURN_ARRAY = False
  if (os.environ.get('SERVER_SOFTWARE', '').startswith('Google App Engine') or
      os.environ.get('SERVER_SOFTWARE', '').startswith('Development')):
    logging.warning('stub out fcntl')
    sys.modules['fcntl'] = 1
  from tlslite.x509 import X509

from tlslite.utils.keyfactory import parsePEMKey


def StrToArray(s):
  """Return an array of bytes or bytearray for a string.

  Return type depends on tlslite version
  Args:
    s: str
  Returns:
    array.array/bytearray instance
  """
  if _RETURN_ARRAY:
    return array.array('B', s)
  return bytearray(s)
