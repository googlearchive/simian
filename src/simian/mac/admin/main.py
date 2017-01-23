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
"""Main module with WSGI app and URL mappings for the admin UI."""

import webapp2

from google.appengine.ext import webapp

from simian import settings
from simian.mac.admin import acl_groups
from simian.mac.admin import applesus
from simian.mac.admin import broken_clients
from simian.mac.admin import config
from simian.mac.admin import groups
from simian.mac.admin import host
from simian.mac.admin import ip_blacklist
from simian.mac.admin import lock_admin
from simian.mac.admin import manifest_modifications
from simian.mac.admin import misc
from simian.mac.admin import package
from simian.mac.admin import package_alias
from simian.mac.admin import packages
from simian.mac.admin import panic
from simian.mac.admin import release_report
from simian.mac.admin import summary
from simian.mac.admin import tags
from simian.mac.admin import upload_icon
from simian.mac.admin import uploadpkg


webapp.template.register_template_library(
    'simian.mac.admin.custom_filters')


app = webapp2.WSGIApplication([
    (r'/admin/?$', summary.Summary),

    (r'/admin/acl_groups/?$', acl_groups.ACLGroups),
    (r'/admin/acl_groups/([\w\-\_\.\s\%]+)/?$', acl_groups.ACLGroups),

    (r'/admin/applesus/?$', applesus.AppleSUSAdmin),
    (r'/admin/applesus/([\w\-]+)/?$', applesus.AppleSUSAdmin),
    (r'/admin/applesus/([\w\-]+)/([\d\w\-]+)$', applesus.AppleSUSAdmin),

    (r'/admin/brokenclients/?$', broken_clients.BrokenClients),

    (r'/admin/config/?$', config.Config),

    (r'/admin/host/([\w\-\_\.\=\|\%, ]+)/?$', host.Host),

    (r'/admin/ip_blacklist/?$', ip_blacklist.IPBlacklist),

    (r'/admin/lock_admin/?$', lock_admin.LockAdmin),

    (r'/admin/release_report/?$', release_report.ReleaseReport),

    (r'/admin/manifest_modifications/?$',
     manifest_modifications.ManifestModifications),

    (r'/admin/package/?$', package.Package),
    (r'/admin/package/([\w\-\_\.\s\%\+]+)/?$', package.Package),

    (r'/admin/package_alias/?$', package_alias.PackageAlias),

    (r'/admin/packages/?$', packages.Packages),
    (r'/admin/packages/([\w\-]+)/?', packages.Packages),

    (r'/admin/panic/?$', panic.AdminPanic),

    (r'/admin/proposals/?$', packages.PackageProposals),
    (r'/admin/proposals/([\w\-]+)/?', packages.PackageProposals),

    (r'/admin/tags/?$', tags.Tags),
    (r'/admin/groups/?$', groups.Groups),

    (r'/admin/uploadpkg/?$', uploadpkg.UploadPackage),
    (r'/admin/upload_icon/([\w\-\_\.\s\%]+)/?$', upload_icon.UploadIcon),

    (r'/admin/([\w\-\_\.\=\|\%]+)$', misc.Misc),
    (r'/admin/([\w\-\_\.\=\|\%]+)/([\w\-\_\.\=\|\%]+)$', misc.Misc),
    ], debug=settings.DEBUG)
