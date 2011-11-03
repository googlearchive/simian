#!/usr/bin/env python
# 
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Main module for Simian API including wsgi URL mappings."""



from google.appengine.ext import webapp
from simian.mac.api import dynamic_manifest
from simian.mac.api import info


class ServeHello(webapp.RequestHandler):
  """Serve hello page."""

  def get(self):
    """Handle GET."""
    self.response.out.write('<p>You\'ve reached the Simian API!</p>')


URLS = [
    (r'/api/dynamic_manifest/?', dynamic_manifest.DynamicManifest),
    (r'/api/dynamic_manifest/([^/]+)/([^/]+)/?',
     dynamic_manifest.DynamicManifest),
    (r'/api/dynamic_manifest/([^/]+)/([^/]+)/([^/]+)/?',
     dynamic_manifest.DynamicManifest),
    (r'/api/info/?',
     info.InfoHandler),
    (r'/api/info/([^/]+)/?',
     info.InfoHandler),
    (r'/api/?$', ServeHello),
]