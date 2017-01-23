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
"""serve icons from GCS."""
import base64
import httplib
import logging

import cloudstorage as gcs
from simian import settings
from simian.mac.common import auth
from simian.mac.munki import handlers


class Icons(handlers.AuthenticationHandler):
  """Handler for /icons/."""

  def get(self, name):
    auth.DoAnyAuth()
    try:
      bucket = settings.ICONS_GCS_BUCKET
    except AttributeError:
      logging.warning('Dedicated icons GCS bucket is not set.')
      self.abort(httplib.BAD_REQUEST)

    name = name.split('.')[0]
    icon_path = '/%s/%s.png' % (bucket, base64.urlsafe_b64encode(name))

    try:
      with gcs.open(icon_path, 'r') as gcs_file:
        self.response.headers['Content-Type'] = 'image/png'
        self.response.write(gcs_file.read())
    except gcs.NotFoundError:
      self.abort(httplib.NOT_FOUND)
