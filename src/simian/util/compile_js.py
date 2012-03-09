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
# ./compile_js.py <path_to_input_js_file> <path_to_output_js_file>

import httplib
import urllib
import sys

CLOSURE_SERVICE_DOMAIN = 'release-cl27858223-1330131679.closure-compiler.appspot.com'

input_js_file = sys.argv[1]
output_js_file = sys.argv[2]

js_source = open(input_js_file, 'r').read()

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