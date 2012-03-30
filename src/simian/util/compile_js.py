#!/usr/bin/env python
# 
# Copyright 2012 Google Inc. All Rights Reserved.
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
#
# Uses Closure Compiler Service API to compile JavaScript file.
# ./compile_js.py <path_to_input_js_file> ... <path_to_output_js_file>

import httplib
import urllib
import re
import sys

CLOSURE_SERVICE_DOMAIN = 'closure-compiler.appspot.com'

input_js_files = sys.argv[1:len(sys.argv)-1]
output_js_file = sys.argv[-1]

# Loop over all input JavaScript files and concatenate the source.
js_source = []
provides_and_requires = []
for f in input_js_files:
  for line in open(f, 'r').readlines():
    line = line.strip()
    if line.startswith('goog.provide') or line.startswith('goog.require'):
      # Store goog.provide and goog.require lines separately, so they can
      # be moved to the top of the concatenated JavaScript source.
      provides_and_requires.append(line)
    elif line.startswith('* @fileoverview'):
      pass  # Omit @fileoverview docstrings; Closure Compiler doesn't like > 1.
    else:
      js_source.append(line)

# Sort the goog.provides and goog.requires lines, to ensure dep integrity.
provides_and_requires = sorted(set(provides_and_requires))
# Concatenate goog.provides, goog.requires, and all other lines in that order.
js_source = provides_and_requires + js_source
js_source = '\n'.join(js_source)

# Param docs: https://developers.google.com/closure/compiler/docs/api-ref
params = urllib.urlencode([
    ('js_code', js_source),
    ('compilation_level', 'ADVANCED_OPTIMIZATIONS'),
    ('output_format', 'text'),
    ('output_info', 'compiled_code'),
    ('use_closure_library', True),
  ])

# Always use the following value for the Content-type header.
headers = { "Content-type": "application/x-www-form-urlencoded" }
conn = httplib.HTTPConnection(CLOSURE_SERVICE_DOMAIN)
conn.request('POST', '/compile', params, headers)
response = conn.getresponse()
response_text = response.read()
conn.close

if response.status != 200 or response_text.startswith('Error'):
  print >>sys.stderr, 'JS compilation failed: %s' % response_text
  sys.exit(1)

f = open(output_js_file, 'w')
f.write(response_text)
f.close()