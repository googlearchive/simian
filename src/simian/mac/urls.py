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

"""Main module for Simian including wsgi URL mappings."""



from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from simian.mac.admin import stats as admin_stats
from simian.mac.admin import applesus as applesus_admin
from simian.mac.admin import panic as admin_panic
from simian.mac.admin import manifest_modifications
from simian.mac.admin import package_alias
from simian.mac.api import urls as api_urls
from simian.mac.munki.handlers import auth
from simian.mac.munki.handlers import uauth
from simian.mac.munki.handlers import applesus
from simian.mac.munki.handlers import catalogs
from simian.mac.munki.handlers import manifests
from simian.mac.munki.handlers import pkgs
from simian.mac.munki.handlers import pkgsinfo
from simian.mac.munki.handlers import reports
from simian.mac.munki.handlers import deletepkg
from simian.mac.munki.handlers import uploadfile
from simian.mac.munki.handlers import uploadpkg


class RedirectToAdmin(webapp.RequestHandler):
  """Redirect the request to the Admin page."""

  def get(self):
    """Handle GET."""
    self.redirect('/admin')


application = webapp.WSGIApplication(
    api_urls.URLS + [
    # GET Apple Software Update Service catalog with header client-id.
    (r'/applesus/?$', applesus.AppleSUS),
    # GET/PUT Apple Software Update Service catalogs.
    (r'/applesus/([\w\-\_\.\=\|\%]+)/?$', applesus.AppleSUS),
    # GET munki catalogs.
    (r'/catalogs/([\w\-\.]+)$', catalogs.Catalogs),
    # GET munki manifests.
    (r'/manifests/([\w\-\_\.\=\|\%]+)$', manifests.Manifests),
    # GET munki packages.
    (r'/pkgs/([\w\-\. \%]+)$', pkgs.Packages),
    # GET list of all munki packages.
    (r'/pkgsinfo/?$', pkgsinfo.PackagesInfo),
    # GET munki pkginfo, PUT updated pkginfo
    (r'/pkgsinfo/([\w\-\_\.\=\|\%]+)$', pkgsinfo.PackagesInfo),
    # POST to delete a munki pkginfo/package pair.
    (r'/deletepkg$', deletepkg.DeletePackage),
    # POST to upload a munki pkginfo/package pair.
    (r'/uploadpkg$', uploadpkg.UploadPackage),
    # POST reports from munki.
    (r'/reports$', reports.Reports),
    # PUT uploadfile from munki.
    (r'/uploadfile/([\w\-]+)/([\w\-\.]+)$', uploadfile.UploadFile),
    # GET/POST Apple SUS admin.
    (r'/admin/applesus/?$', applesus_admin.AppleSUSAdmin),
    (r'/admin/applesus/([\w\-]+)/([\d\w\-]+)$', applesus_admin.AppleSUSAdmin),
    # GET/POST Manifest Modifications admin.
    (r'/admin/manifest_modifications/?$',
     manifest_modifications.ManifestModifications),
    # GET/POST Manifest Modifications admin.
    (r'/admin/package_alias/?$', package_alias.PackageAlias),
    # GET or POST admin panic interface,
    (r'/admin/panic/?$', admin_panic.AdminPanic),
    # GET reports pages.
    (r'/admin/?$', admin_stats.Stats),
    (r'/admin/([\w\-\_\.\=\|\%]+)$', admin_stats.Stats),
    (r'/admin/([\w\-\_\.\=\|\%]+)/([\w\-\_\.\=\|\%]+)$',
     admin_stats.Stats),
    # GET or POST user auth.
    (r'/uauth/?$', uauth.UserAuth),
    # GET auth logout, POST munki auth.
    (r'/auth/?$', auth.Auth),
    (r'/repair/?$', pkgs.ClientRepair),
    (r'/repair/([\w\-\_\.\=\|\%]+)$', pkgs.ClientRepair),
    (r'/_ah/warmup', RedirectToAdmin),
    (r'/?$', RedirectToAdmin),
    ], debug=True)


def main():
    run_wsgi_app(application)


if __name__ == '__main__':
    main()