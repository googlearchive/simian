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
"""Tags admin handler."""

import httplib
import urllib

from google.appengine.ext import db

from simian.mac import admin
from simian.mac import models
from simian.mac.common import auth


class Tags(admin.AdminHandler):
  """Handler for /admin/tags."""

  def get(self):
    """GET handler."""
    can_mod_tags = (
        self.IsAdminUser() or auth.IsSupportUser or auth.IsSecurityUser())
    tags = models.Tag.all()
    tags = sorted(tags, key=lambda t: unicode.lower(t.key().name()))
    d = {'tags': tags, 'can_mod_tags': can_mod_tags,
         'report_type': 'tags'}
    self.Render('tags.html', d)

  @admin.AdminHandler.XsrfProtected('tags')
  def post(self):
    """POST handler."""
    can_mod_tags = (
        self.IsAdminUser() or auth.IsSupportUser or auth.IsSecurityUser())
    if not can_mod_tags:
      return

    tag = self.request.get('tag').strip()
    tag = urllib.unquote(tag)
    action = self.request.get('action')
    if action == 'create':
      t = models.Tag(key_name=tag)
      uuid = self.request.get('uuid')
      if uuid:
        key = db.Key.from_path('Computer', uuid)
        t.keys.append(key)
      t.put()
      msg = 'Tag successfully saved.'
    elif action == 'delete':
      tag_manifest_mods = models.TagManifestModification.all().filter(
          'tag_key_name =', tag).get()
      if tag_manifest_mods:
        msg = 'Tag not deleted as it\'s being used for Manifest Modifications.'
      else:
        t = models.Tag.get_by_key_name(tag)
        if t:
          t.delete()
        else:
          self.error(httplib.NOT_FOUND)
          return
        msg = 'Tag successfully deleted.'
    elif action == 'change':
      uuid = self.request.get('uuid')
      add_tag = self.request.get('add') == '1'
      t = models.Tag.get_by_key_name(tag)
      if not t:
        self.error(httplib.NOT_FOUND)
        return

      key = db.Key.from_path('Computer', uuid)
      if add_tag:
        t.keys.append(key)
      else:
        if key in t.keys:
          t.keys.remove(key)
      t.put()
      msg = 'Tag successfully modified'

    self.redirect('/admin/tags?msg=%s' % msg)
