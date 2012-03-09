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

"""Info API URL handlers."""



import datetime
import logging
import urllib

try:
  import icalendar
except ImportError:
  icalendar = None

from google.appengine.ext import webapp
from google.appengine.ext import db
from simian import settings
from simian.mac import common
from simian.mac import models
from simian.mac.common import applesus


API_INFO_KEY = settings.API_INFO_KEY


class Error(Exception):
  """Class for domain specific exceptions."""


class InfoHandler(webapp.RequestHandler):
  """Handler for /api/info/*."""

  def _DisplayAppleSusPromoCalendar(self):
    """Display upcoming Apple SUS updates in iCal format."""
    now = datetime.datetime.utcnow().date()
    query = models.AppleSUSProduct.all().order('-apple_mtime')
    dates = {}
    # NOTE(user): the following adds about 700ms onto the request, so we may
    #             want to pre-calculate this in a cron in the future.
    for p in query:
      if p.manual_override:
        continue
      if not common.UNSTABLE in p.tracks:
        continue
      if common.STABLE not in p.tracks:
        p.stable_promote_date = applesus.GetAutoPromoteDate(common.STABLE, p)
      if common.TESTING not in p.tracks:
        p.testing_promote_date = applesus.GetAutoPromoteDate(common.TESTING, p)

      if hasattr(p, 'stable_promote_date') and p.stable_promote_date >= now:
        dates.setdefault(p.stable_promote_date, []).append(p)
      if hasattr(p, 'testing_promote_date') and p.testing_promote_date >= now:
        dates.setdefault(p.testing_promote_date, []).append(p)

    dtstamp = datetime.datetime.utcnow()
    cal = icalendar.Calendar()

    for d in dates:
      e = icalendar.Event()
      e.add('dtstamp', dtstamp)
      e.add('summary', 'Apple SUS auto-promote')
      e.add('dtstart', d)
      e.add('transp', 'TRANSPARENT')

      products = {common.TESTING: [], common.STABLE: []}
      for p in dates[d]:
        track = None
        if p.stable_promote_date == d:
          track = common.STABLE
        elif p.testing_promote_date == d:
          track = common.TESTING

        products[track].append(
            '  %s %s (%s)' % (p.name, p.version, p.product_id))

      desc = []
      for track in [common.STABLE, common.TESTING]:
        if not products[track]:
          continue
        desc.append('Auto-promoting to %s:' % track.upper())
        desc.append('\n'.join(products[track]))

      e.add('description', '\n\n'.join(desc))
      e['uid'] = '%s-simian-applesus' % d.strftime('%Y%m%d')
      cal.add_component(e)

    self.response.headers['Content-Type'] = 'text/calendar'
    self.response.out.write(cal.as_string())

  def get(self, info_type=None):
    """Get handler.

    Args:
      info_type: str, type of info we want.
    """
    key = self.request.get('key')

    if not API_INFO_KEY:
      logging.warning('API_INFO_KEY is unset; blocking all API info requests.')
      self.response.set_status(401)
      return
    elif key != API_INFO_KEY:
      self.response.set_status(401)
      return

    if not icalendar:
      logging.warning('icalendar import failed, so feeds are disabled.')
      self.response.set_status(404)
    elif info_type == 'applesus_promo_cal':
      self._DisplayAppleSusPromoCalendar()
    else:
      self.response.set_status(404)