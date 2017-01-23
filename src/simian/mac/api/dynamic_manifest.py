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
"""DynamicManifest API URL handlers."""

import httplib
import json
import logging
import urllib

from google.appengine.ext import db

from simian import settings
from simian.mac import models
from simian.mac.common import auth
from simian.mac.munki import handlers


class Error(Exception):
  """Class for domain specific exceptions."""


class InvalidModificationType(Error):
  """An invalid modification type was given."""


class DynamicManifest(handlers.AuthenticationHandler):
  """Handler for /api/dynamic_manifest/"""

  def __init__(self, *args, **kwargs):
    self.user = None
    super(DynamicManifest, self).__init__(*args, **kwargs)

  def _ParseParameters(self, mod_type, target, pkg_name):
    """ParseParameters instance variables.

    Args:
      mod_type: str modification type, e.g. owner, site, os_version.
      target: str modification target, e.g. foouser, NYC, 10.6.7.
      pkg_name: str Munki package name, e.g. FooPkg.
    """
    if mod_type not in models.MANIFEST_MOD_MODELS:
      logging.warning('Invalid modification type specified: %s', mod_type)
      raise InvalidModificationType(mod_type)
    self.mod_type = mod_type
    self.model = models.MANIFEST_MOD_MODELS.get(self.mod_type, None)
    if target:
      self.target = urllib.unquote(target)
    else:
      self.target = None
    if pkg_name:
      self.pkg_name = urllib.unquote(pkg_name)
    else:
      self.pkg_name = None
    self.key_name = '%s##%s' % (self.target, self.pkg_name)
    self.install_types = self.request.get_all('install_types')
    # Disallow manifests to be set for owner modifications.
    if mod_type == 'owner':
      self.manifests = []
    else:
      self.manifests = self.request.get_all('manifests')

  def _PutMod(self):
    """Ensures required parameters are set and puts a dynamic manifest mod.

    Raises:
      ValueError: not all required parameters were set.
      db.Error: there was an error calling db.Model.put().
    """
    for var in [self.mod_type, self.target, self.pkg_name, self.install_types]:
      if not var:
        logging.warning('A required parameter was not set.')
        raise ValueError

    mod = self.model(key_name=self.key_name)
    mod.enabled = True
    mod.target = self.target
    mod.value = self.pkg_name
    mod.manifests = self.manifests
    mod.install_types = self.install_types
    mod.user = self.user
    logging.debug('Putting new dynamic manifest mod of type %s for %s: %s',
                  self.mod_type, self.target, self.pkg_name)
    try:
      mod.put()
    except db.Error:
      logging.exception('error on DynamicManifest.put()')
      raise
    models.BaseManifestModification.ResetModMemcache(
        self.mod_type, self.target)

  def _CheckApiKey(self):
    key = self.request.headers.get('X-Simian-API-Info-Key')

    if not settings.API_INFO_KEY:
      logging.warning('API_INFO_KEY is unset; blocking all API info requests.')
      self.response.abort(httplib.UNAUTHORIZED)
    elif key != settings.API_INFO_KEY:
      self.response.abort(httplib.UNAUTHORIZED)

  def _UserAuthWithApiKeyCheck(self):
    # TODO(user): setup DoUserAuth require_level=gaeserver.LEVEL_API_READONLY.
    self.user = auth.DoUserAuth(is_admin=True)
    self._CheckApiKey()

  def get(self, mod_type=None, target=None, pkg_name=None):
    """DynamicManifest get handler.

    Returns:
      A webapp.Response() response.
    """
    self._UserAuthWithApiKeyCheck()
    try:
      self._ParseParameters(mod_type, target, pkg_name)
    except InvalidModificationType:
      self.error(httplib.NOT_FOUND)
      return

    if not self.target:
      logging.warning('Target is required but was not specified.')
      self.error(httplib.BAD_REQUEST)
      return

    query = self.model.all().filter('%s =' % self.mod_type, self.target)
    if self.pkg_name:
      query.filter('value =', self.pkg_name)

    mods = [m.Serialize() for m in query]
    if not mods:
      self.error(httplib.NOT_FOUND)
      return

    self.response.headers['Content-Type'] = 'application/json'
    self.response.out.write(mods)

  def put(self, mod_type=None, target=None, pkg_name=None):
    """DynamicManifest put handler.

    Returns:
      A webapp.Response() response.
    """
    self._UserAuthWithApiKeyCheck()

    try:
      self._ParseParameters(mod_type, target, pkg_name)
    except InvalidModificationType:
      self.error(httplib.NOT_FOUND)
      return

    try:
      self._PutMod()
    except ValueError:
      self.error(httplib.BAD_REQUEST)
    except db.Error:
      self.error(httplib.INTERNAL_SERVER_ERROR)

  def delete(self, mod_type=None, target=None, pkg_name=None):
    """DynamicManifest delete handler.

    Returns:
      A webapp.Response() response.
    """
    self._UserAuthWithApiKeyCheck()

    try:
      self._ParseParameters(mod_type, target, pkg_name)
    except InvalidModificationType:
      self.error(httplib.NOT_FOUND)
      return

    mod = self.model.get_by_key_name(self.key_name)
    if not mod:
      self.error(httplib.NOT_FOUND)
      return

    try:
      mod.delete()
    except db.Error:
      logging.exception('error on DynamicManifest.delete()')
      self.error(httplib.INTERNAL_SERVER_ERROR)

  def post(self):
    """DynamicManifest post handler."""
    # TODO(user): setup DoUserAuth require_level=gaeserver.LEVEL_API_DYN_MAN.
    try:
      self.user = auth.DoOAuthAuth()
    except auth.NotAuthenticated:
      # OAuth was either not used or failed, so perform regular user auth.
      if not self.user:
        self._UserAuthWithApiKeyCheck()

    mod_type = self.request.get('mod_type')
    target = self.request.get('target')
    mutate = self.request.get('mutate', 'true').lower() == 'true'
    if not mutate:
      logging.info('Enabling dry-run mode')

    pkg_alias = self.request.get('pkg_alias')
    if pkg_alias:
      pkg_name = models.PackageAlias.ResolvePackageName(pkg_alias)
      if not pkg_name:
        logging.info('Package alias not found: %s', pkg_alias)
        self.error(httplib.NOT_FOUND)
        return
      logging.debug('Found pkg_name=%s for pkg_alias=%s', pkg_name, pkg_alias)
    else:
      pkg_name = self.request.get('pkg_name')

    try:
      self._ParseParameters(mod_type, target, pkg_name)
    except InvalidModificationType:
      self.error(httplib.NOT_FOUND)
      return


    try:
      if mutate:
        self._PutMod()
      self.response.headers['Content-Type'] = 'application/json'
      self.response.out.write(json.dumps([{'pkg_name': pkg_name}]))
    except ValueError:
      self.error(httplib.BAD_REQUEST)
    except db.Error:
      self.error(httplib.INTERNAL_SERVER_ERROR)
