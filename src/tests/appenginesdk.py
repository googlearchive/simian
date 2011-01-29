#!/usr/bin/env python
# 
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Load App Engine package from zip."""



import sys
import os
try:
  import google.appengine.runtime
except ImportError:
  from pkgutil import extend_path as _extend_path
  import google
  _path = '%s/gae_server.zip' % os.path.dirname(os.path.realpath(__file__))
  google.__path__ = _extend_path(['%s/google' % _path], google.__name__)
  import google.appengine
  google.appengine.__path__ = _extend_path(['%s/google/appengine' % _path], google.__name__)
import google.appengine.runtime