#!/usr/bin/env python
#
# Copyright 2015 Google Inc. All Rights Reserved.
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
"""API handler for package info."""

import json
import logging
import webapp2

from simian import settings
from simian.mac import models

API_INFO_KEY = settings.API_INFO_KEY


PKGINFO_PLIST_KEYS_AND_DEFAULTS = (
    ('display_name', None),
    ('autoremove', False),
    ('forced_install', False),
    ('unattended_install', False),
    ('uninstallable', True),
    ('version', None)
)


class PackageInfo(webapp2.RequestHandler):

  def get(self):
    key = self.request.get('key')

    if not API_INFO_KEY:
      logging.warning('API_INFO_KEY is unset; blocking all API info requests.')
      self.response.set_status(401)
      return
    elif key != API_INFO_KEY:
      self.response.set_status(401)
      return

    output = {}

    for package in models.PackageInfo.all():
      output[package.filename] = {
          'name': package.name,
          'catalogs': package.catalogs,
          'created': package.created.isoformat(),
          'install_types': package.install_types,
          'manifests': package.manifests,
          'munki_name': package.munki_name,
          'mtime': package.mtime.isoformat(),
      }

      for key, default in PKGINFO_PLIST_KEYS_AND_DEFAULTS:
        output[package.filename][key] = package.plist.get(key, default)

    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(json.dumps(output))
