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
#
# Do NOT change the above sha-bang line unless if you know what you are doing.
#
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


REQUIRE_BASE = [
    'setuptools>=18.2',
    'pyasn1>=0.1.2',
    'tlslite==0.4.9',
    'pyyaml>=3.10',
    'requests',
]

REQUIRE_SETUP = REQUIRE_BASE + [
    'google_apputils==0.4',  # 0.4.1: ezsetup broken, 0.4.2: testbase broken
    'python-dateutil>=1.4,<2',  # because of google_apputils
    'python-gflags==2.0',  # gflags 3.0+ requires python2.7
]

REQUIRE_TEST = REQUIRE_BASE + [
    'mock',
    'mox>=0.5.3',
    'Pillow',  # needed for google_apputils init_all_stubs() (for imging stub)
    'pyfakefs',
    'unittest2',
    'webapp2',
    'webtest',
    'WebOb>=1.2',  # webtest requires >=1.2.
]

REQUIRE_INSTALL = REQUIRE_BASE

SIMIAN_STUBS = [
    ('simian_preflight', 'RunSimianPreflight'),
    ('simian_postflight', 'RunSimianPostflight'),
]
SIMIAN_ENTRY_POINTS = ['%s = simian.stubs:%s' % s for s in SIMIAN_STUBS]

setup(
  name = 'simian',
  version = '2.4',
  url = 'https://github.com/google/simian',
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

  setup_requires = REQUIRE_SETUP,
  install_requires = REQUIRE_INSTALL,
  tests_require = REQUIRE_TEST,

  google_test_dir = 'src/tests',
)
