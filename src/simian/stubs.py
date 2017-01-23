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
"""Stub entry points for Simian programs."""

from google.apputils import run_script_module


def RunSimianPreflight():
  from simian.mac.client import preflight
  return run_script_module.RunScriptModule(preflight)


def RunSimianPostflight():
  from simian.mac.client import postflight
  return run_script_module.RunScriptModule(postflight)
