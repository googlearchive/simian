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

try:
  from setuptools import setup, find_packages
except ImportError:
  print 'required Python setuptools is missing.'
  print 'install from http://pypi.python.org/pypi/setuptools'
  raise SystemExit(1)


REQUIRE = [
    'setuptools>=0.6c9',     # fix bugs with old version on Leopard
    'google_apputils>=0.2',
    'python-dateutil>=1.4',  # because of google_apputils
    'pyasn1',
    'tlslite',
    'M2Crypto',
    'pyyaml',
    'icalendar',
]

SIMIAN_STUBS = [
    ('simianadmin', 'RunSimianAdmin'),
    ('simianauth', 'RunSimianAuth'),
]
SIMIAN_ENTRY_POINTS = ['%s = simian.stubs:%s' % s for s in SIMIAN_STUBS]

setup(
  name = 'simian',
  version = '1.5.2',
  url = 'http://code.google.com/p/simian',
  license = 'Apache 2.0',
  description = 'An App Engine-based client & server component for Munki',
  author = 'Google',
  author_email = 'simian-eng@googlegroups.com',

  packages = find_packages('src', exclude=['tests']),
  package_dir = {'': 'src'},
  package_data = {
      '': ['*.zip'],
  },
  include_package_data = True,

  entry_points = {
      'console_scripts': SIMIAN_ENTRY_POINTS,
  },

  setup_requires = REQUIRE,
  install_requires = REQUIRE,
  tests_require = REQUIRE + ['mox>=0.5.3', 'webob', 'django'],

  google_test_dir = 'src/tests',
)