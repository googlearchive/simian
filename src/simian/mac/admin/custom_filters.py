#!/usr/bin/env python
# 
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Custom template filters."""




import cgi
import datetime
import re
import time

from google.appengine.ext import webapp

try:
  from django.utils.html import conditional_escape
  from django.utils.safestring import mark_safe
except ImportError:
  # For unit tests, just return the same string.
  mark_safe = lambda x: x
  conditional_escape = lambda x: x


register = webapp.template.create_template_register()


@register.filter
def spacify(value, autoescape=None):
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x
    return mark_safe(re.sub('\s', '&nbsp;', esc(value)))
spacify.needs_autoescape = True


@register.filter
def tracks_display(tracks):
  """Prints out [u][t][s]-style track information for a list of tracks."""
  if not tracks:
    return ''
  html = []
  for track in sorted(tracks, reverse=True):
    html.append(
        '<span class="track %s" title="%s"></span>' % (track, track))
  return mark_safe(''.join(html))


@register.filter
def munki_property(tag, tagname=None):
  """Prints a formatted, colored tag."""
  if not tag:
    return ''
  tags = {
    'managed_installs': 'install',
    'managed_updates': 'update',
    'managed_uninstalls': 'uninstall',
    'optional_installs': 'optional',
    'unattended_install': 'unattd',
  }
  html = '<span class="tags %s" title="%s">%s</span>'
  abbr = tags.get(tag, tag)
  return mark_safe(html % (tagname or tag, tag, abbr))


@register.filter
def munki_properties(tags):
  return mark_safe('\n'.join([munki_property(tag) for tag in tags]))


@register.filter
def munki_property_forcedate(date):
  if not date: return ''
  return mark_safe(munki_property(
      'force install: %s' % date.strftime('%b %d, %Y %I%p').lower(),
      'force_install'))


@register.filter
def avg_download_speed(installs):
  """Returns an avg download speed from a list of models.InstallLog entities."""
  speeds = [i.dl_kbytes_per_sec for i in installs if i.dl_kbytes_per_sec]
  if speeds:
    avg_speed = sum(speeds) / len(speeds)
    return download_speed(avg_speed)
  else:
    return 'N/A'


@register.filter
def download_speed(kbytes_per_second):
  """Returns HTML markup for KB/s."""
  if not kbytes_per_second:  # includes None and 0 intentionally.
    return 'N/A'

  if kbytes_per_second < 1024:
    return '%s KB/s' % kbytes_per_second
  else:
    return '%.2f MB/s' % (float(kbytes_per_second) / 1024)


@register.filter
def host_uuid_link(uuid):
  """Returns an HTML anchor tag linking to the report for the given uuid."""
  return mark_safe('<a href="/admin/host/%s/">%s</a>' % (uuid, uuid))


@register.filter
def uptime_from_seconds(seconds_since_reboot):
  """Converts float seconds_since_reboot to 'N days, hh:mm:ss'."""
  if seconds_since_reboot:
    uptime_days = datetime.timedelta(seconds=seconds_since_reboot).days
    uptime_hms = time.strftime('%H:%M:%S', time.gmtime(seconds_since_reboot))
    return '%d days, %s' % (uptime_days, uptime_hms)
  else:
    return 'unknown'