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
"""Module containing url handler for all Apple SUS related crons.

Classes:
  AppleSUSCatalogSync: syncs SUS catalogs from Apple.
"""

import webapp2

from simian import settings
from simian.mac.cron import applesus
from simian.mac.cron import maintenance
from simian.mac.cron import reports_cache


app = webapp2.WSGIApplication([
    # Apple SUS
    (r'/cron/applesus/catalogsync$', applesus.AppleSUSCatalogSync),
    (r'/cron/applesus/autopromote$', applesus.AppleSUSAutoPromote),


    # Maintenance
    ('/cron/maintenance/authsession_cleanup', maintenance.AuthSessionCleanup),
    ('/cron/maintenance/mark_computers_inactive',
     maintenance.MarkComputersInactive),
    ('/cron/maintenance/verify_packages', maintenance.VerifyPackages),
    ('/cron/maintenance/update_avg_install_durations',
     maintenance.UpdateAverageInstallDurations),

    # Reports Cache
    (r'/cron/reports_cache/([a-z_]+)$', reports_cache.ReportsCache),
    (r'/cron/reports_cache/([a-z_]+)/(.*)$', reports_cache.ReportsCache),
], debug=settings.DEBUG)
