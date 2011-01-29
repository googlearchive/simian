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

    if common.IsPanicModeNoPackages():
      plist_xml = '%s%s' % (plist_module.PLIST_HEAD, plist_module.PLIST_FOOT)
    else:
      manifest_name = client_id['track']
      m = models.Manifest.MemcacheWrappedGet(manifest_name)
      if not m:
        logging.debug('Invalid manifest requested: %s', manifest_name)
        self.response.set_status(404)
        return
      elif not m.enabled:
        logging.debug('Disabled manifest requested: %s', manifest_name)
        self.response.set_status(503)
        return

      plist_xml = GenerateDynamicManifest(m.plist, client_id)

    self.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
    self.response.out.write(plist_xml)


def _ModifyList(l, value):
  """Adds or removes a value from a list.

  Args:
    l: list to modify.
    value: str value; "foo" to add or "-foo" to remove "foo".
  """
  if value.startswith('-'):
    try:
      l.remove(value[1:])
    except ValueError:
      pass  # item is already not a member of the list, so ignore error.
  else:
    l.append(value)


def GenerateDynamicManifest(plist_xml, client_id):
  """Generate a dynamic manifest based on a the various client_id fields.

  Args:
    plist_xml: str XML manifest to start with.
    client_id: dict client_id parsed by common.ParseClientId.
  Returns:
    str XML manifest with any custom modifications based on the client_id.
    """
  manifest = client_id['track']
  # TODO(user): we'll probably want to memcache *all* site modificiations,
  #    since there will be very few, but not hostname/owner modifications as
  #    they'll be widespread after Stuff integration.
  site_mods = models.SiteManifestModification.all().filter(
      'site =', client_id['site'])
  os_version_mods = models.OSVersionManifestModification.all().filter(
      'os_version =', client_id['os_version'])
  # host_mods = mods.HostManifestModification.all().filter(
  #   'hostname =', client_id['hostname'])
  host_mods = []  # temporary.

  def __ApplyModifications(manifest, mod, plist):
    """Applies a manifest modification if the manifest matches mod manifest."""
    if mod.enabled and manifest in mod.manifests:
      logging.debug(
          'Applying manifest mod: %s %s', mod.install_type, mod.value)
      plist_module.UpdateIterable(
          plist, mod.install_type, mod.value, default=[], op=_ModifyList)

  if site_mods or host_mods or os_version_mods:
    plist = plist_module.MunkiManifestPlist(plist_xml)
    plist.Parse()
    for mod in site_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in host_mods:
      __ApplyModifications(manifest, mod, plist)
    for mod in os_version_mods:
      __ApplyModifications(manifest, mod, plist)
    plist_xml = plist.GetXml()
  return plist_xml
