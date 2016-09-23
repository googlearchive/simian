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
"""Main module for Simian including wsgi URL mappings."""

import webapp2

from simian import settings
from simian.mac.munki.handlers import applesus
from simian.mac.munki.handlers import auth
from simian.mac.munki.handlers import catalogs
from simian.mac.munki.handlers import manifests
from simian.mac.munki.handlers import pkgs
from simian.mac.munki.handlers import pkgsinfo
from simian.mac.munki.handlers import reports
from simian.mac.munki.handlers import uploadfile


class RedirectToAdmin(webapp2.RequestHandler):
  """Redirect the request to the Admin page."""

  def get(self):
    """Handle GET."""
    self.redirect('/admin')


app = webapp2.WSGIApplication([
    # GET Apple Software Update Service catalog with header client-id.
    (r'/applesus/?$', applesus.AppleSUS),
    (r'/applesus/([^/]+)$', applesus.AppleSUS),
    (r'/applesus/([^/]+)/([^/]+)?$', applesus.AppleSUS),
    # GET munki catalogs.
    (r'/catalogs/([\w\-\.]+)$', catalogs.Catalogs),
    # GET munki manifests.
    (r'/manifests/([\w\-\_\.\=\|\%]+)$', manifests.Manifests),
    # GET munki packages.
    (r'/pkgs/([\w\-\. \%]+)$', pkgs.Packages),
    (r'/pkgs\-userauth/([\w\-\. \%]+)$', pkgs.Packages),  # forces user auth.
    # GET list of all munki packages.
    (r'/pkgsinfo/?$', pkgsinfo.PackagesInfo),
    # GET munki pkginfo, PUT updated pkginfo
    (r'/pkgsinfo/([\w\-\_\.\=\|\%]+)$', pkgsinfo.PackagesInfo),
    # POST reports from munki.
    (r'/reports$', reports.Reports),
    # PUT uploadfile from munki.
    (r'/uploadfile/([\w\-]+)/([\w\-\.]+)$', uploadfile.UploadFile),
    # GET auth logout, POST munki auth.
    (r'/auth/?$', auth.Auth),
    (r'/repair/?$', pkgs.ClientRepair),
    (r'/repair/([\w\-\_\.\=\|\%]+)$', pkgs.ClientRepair),
    (r'/_ah/warmup', RedirectToAdmin),
    (r'/?$', RedirectToAdmin),
], debug=settings.DEBUG)
