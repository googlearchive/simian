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

"""Manifest URL handlers."""



import logging
import re
import urllib
from google.appengine.api import users
from google.appengine.ext import webapp
from simian.mac import models
from simian.auth import gaeserver
from simian.mac.common import auth
from simian.mac.munki import common
from simian.mac.munki import handlers
from simian.mac.munki import plist as plist_module


class Manifests(handlers.AuthenticationHandler, webapp.RequestHandler):
  """Handler for /manifests/"""

  def get(self, client_id=''):
    """Manifest get handler.

    Args:
      client_id: optional str client_id; only needed for user requests.

    Returns:
      A webapp.Response() response.
    """
    session = auth.DoAnyAuth()
    if hasattr(session, 'uuid'):  # DoMunkiAuth returned session, override uuid.
      # webapp's request.headers.get() returns None if the key doesn't exist
      # which breaks urllib.unquote(), so return empty string default instead.
      client_id = self.request.headers.get('X-munki-client-id', '')
      if not client_id:
        logging.warning('Client ID header missing: %s', session.uuid)
      client_id = urllib.unquote(client_id)
      client_id = common.ParseClientId(client_id, uuid=session.uuid)
    else:  # DoUserAuth was called; setup client id
      client_id = urllib.unquote(client_id)
      client_id = common.ParseClientId(client_id)

    try:
      plist_xml = common.GetComputerManifest(
          client_id=client_id, packagemap=False)
    except common.ManifestNotFoundError, e:
      logging.debug('Invalid manifest requested: %s', str(e))
      self.response.set_status(404)
      return
    except common.ManifestDisabledError, e:
      logging.debug('Disabled manifest requested: %s', str(e))
      self.response.set_status(503)
      return

    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml)