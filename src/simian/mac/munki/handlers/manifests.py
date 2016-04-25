#!/usr/bin/env python
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Manifest URL handlers."""

import logging

from simian.mac.common import auth
from simian.mac.munki import common
from simian.mac.munki import handlers


class Manifests(handlers.AuthenticationHandler):
  """Handler for /manifests/"""

  def get(self, client_id_str=''):
    """Manifest get handler.

    Args:
      client_id_str: optional str client_id; only needed for user requests.

    Returns:
      A webapp.Response() response.
    """
    session = auth.DoAnyAuth()
    client_id = handlers.GetClientIdForRequest(
        self.request, session=session, client_id_str=client_id_str)

    try:
      plist_xml = common.GetComputerManifest(
          client_id=client_id, packagemap=False)
    except common.ManifestNotFoundError, e:
      logging.warning('Invalid manifest requested: %s', str(e))
      self.response.set_status(404)
      return
    except common.ManifestDisabledError, e:
      logging.info('Disabled manifest requested: %s', str(e))
      self.response.set_status(503)
      return
    except common.Error, e:
      logging.exception(
          '%s, client_id_str=%s', str(e.__class__.__name__), client_id_str)
      self.response.set_status(503)
      return

    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml)
