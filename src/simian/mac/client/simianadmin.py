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

"""Simian CLI."""



import sys
import warnings
warnings.filterwarnings(
    'ignore',
    '.*Python 2\.\d is unsupported; use 2.\d.*', DeprecationWarning, '.*', 0)
from simian.mac.client import cli as mac_cli
from simian.client import cli as base_cli


if __name__ == '__main__':
  warnings.warn(
    'The cli admin client is deprecated. It may partially or fully '
    'fail to provide admin functionality.')
  base_cli.main(sys.argv, mac_cli.SimianCliClient)