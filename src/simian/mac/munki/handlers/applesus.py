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
"""Apple Software Update Service Catalog URL handlers."""

import base64
import httplib
import json
import logging
import os

from simian.auth import gaeserver
from simian.mac import models
from simian.mac.munki import common
from simian.mac.munki import handlers
from simian.mac.munki.handlers import auth


MUNKI_CLIENT_ID_HEADER_KEY = 'X-munki-client-id'


def _EncodeMsg(d):
  data = json.dumps(d)
  return base64.urlsafe_b64encode(data)


def _DecodeMsg(data):
  try:
    data = base64.urlsafe_b64decode(data)
  except TypeError:
    raise ValueError
  return json.loads(data)


class AppleSUS(handlers.AuthenticationHandler):
  """Handler for /applesus/"""

  def get(self, msg='', unused_provided_by_softwareupdate=''):
    """AppleSUS get handler.

    Args:
      name: str, catalog name to get.
      unused_provided_by_softwareupdate: Apple softwareupdate appends filename
        to our url.
    """
    if msg:
      # Clients first POST to this handler and receive a URL with an embedded,
      # encrypted cookie-set containing an Auth1Token.  When GET is called on
      # this URL, we must decode and unpack the cookie/Auth1Token, and set
      # the HTTP_COOKIE environment variable for DoMunkiAuth to validate.
      try:
        d = _DecodeMsg(msg)
      except ValueError:
        self.response.set_status(httplib.BAD_REQUEST)
        return
      os.environ['HTTP_COOKIE'] = str(d['cookies'])
      self.request.headers[MUNKI_CLIENT_ID_HEADER_KEY] = d['header']

    session = gaeserver.DoMunkiAuth(require_level=gaeserver.LEVEL_APPLESUS)
    client_id = handlers.GetClientIdForRequest(self.request, session=session)

    # get only major.minor os_version, stripping miniscule versioning.
    # i.e. 10.6.6 becomes 10.6, 10.23.6.x.x becomes 10.23
    full_os_version = client_id.get('os_version', '')
    os_version = '.'.join(full_os_version.split('.', 2)[:2])
    track = client_id.get('track', 'stable')
    catalog_name = '%s_%s' % (os_version, track)

    catalog = models.AppleSUSCatalog.MemcacheWrappedGet(catalog_name)
    if not catalog:
      logging.warning('Apple SUS catalog not found: %s', catalog_name)
      self.response.set_status(httplib.NOT_FOUND)
      return

    header_date_str = self.request.headers.get('If-Modified-Since', '')
    catalog_date = catalog.mtime
    if handlers.IsClientResourceExpired(catalog_date, header_date_str):
      self.response.headers['Last-Modified'] = catalog_date.strftime(
          handlers.HEADER_DATE_FORMAT)
      self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
      self.response.out.write(catalog.plist)
    else:
      self.response.set_status(httplib.NOT_MODIFIED)

  def _SanitazeMunkiHeader(self, munki_header):
    """Leave required fields only."""
    client_id = common.ParseClientId(munki_header)
    return 'os_version=%s|track=%s' % (
        client_id.get('os_version', ''), client_id.get('track', 'stable'))

  def post(self):
    """Returns auth token for get method."""
    session = gaeserver.DoMunkiAuth()

    asd = gaeserver.AuthSessionSimianServer()
    token = None
    for s in asd.GetByUuid(session.uuid):
      if s.level != gaeserver.LEVEL_APPLESUS:
        continue
      if asd.IsExpired(s):
        continue

      assert s.key().name().startswith('t_')
      token = s.key().name()[2:]

    if not token:
      auth1 = gaeserver.AuthSimianServer()
      # create new token suitable only for applesus.
      # original token will be destroyed on postflight.
      token = auth1.SessionCreateUserAuthToken(
          session.uuid, level=gaeserver.LEVEL_APPLESUS)

    munki_header = self.request.headers.get(MUNKI_CLIENT_ID_HEADER_KEY, '')
    # Also store munki header, which contain OS X version and track.
    d = {
        'cookies': auth.CreateAuthTokenCookieStr(token),
        'header': self._SanitazeMunkiHeader(munki_header),
    }

    self.response.out.write(_EncodeMsg(d))
