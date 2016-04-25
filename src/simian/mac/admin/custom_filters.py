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
"""Custom template filters."""

import datetime
import re
import time
import urlparse

from google.appengine.ext import webapp

# TODO(user): remove this _internal hack import; switch away from webapp
#             template rendering throughout the codebase.
try:
  from google.appengine._internal.django.utils.safestring import mark_safe
  from google.appengine._internal.django.utils.html import conditional_escape
except ImportError:
  # For unit tests, just return the same string.
  mark_safe = lambda x: x
  conditional_escape = lambda x: x


register = webapp.template.create_template_register()

# filter names are lower_with_under to match other Django template filters.
# pylint: disable=g-bad-name


@register.filter
def install_count(munki_name, pkgs_dict):
  return pkgs_dict.get(munki_name, {}).get('install_count', '0')


@register.filter
def failure_count(munki_name, pkgs_dict):
  return pkgs_dict.get(munki_name, {}).get('install_fail_count', '0')


@register.filter
def spacify(value, autoescape=None):
  if autoescape:
    esc = conditional_escape
  else:
    esc = lambda x: x
  return mark_safe(re.sub(r'\s', '&nbsp;', esc(value)))
spacify.needs_autoescape = True


@register.filter
def tracks_display(track_dict):
  """Prints out [u][t][s]-style track with pending proposals marked."""
  if not track_dict:
    return ''
  html = []
  for track in sorted(track_dict, reverse=True):
    html.append('<span class="track %s %s" title="%s"></span>' % (
        track, track_dict[track], track))
  return mark_safe(''.join(html))


@register.filter
def tracks_display_no_proposals(track_list):
  """Prints out [u][t][s]-style track with no proposals."""
  if not track_list:
    return ''
  html = []
  for track in sorted(track_list, reverse=True):
    html.append('<span class="track %s" title="%s"></span>' % (
        track, track))
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
      'unattended_uninstall': 'unattended_uninstall',
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
def host_details_link(uri, uuid):
  """Returns a joined URL to host record details page."""
  url = urlparse.urljoin(uri, uuid)
  return mark_safe('<a href="%s" class="host_details">view</a>' % url)


@register.filter
def host_uuid_link(uuid):
  """Returns an HTML anchor tag linking to the report for the given uuid."""
  return mark_safe(
      '<a href="/admin/host/%s/" class="uuidhover">%s</a>' % (uuid, uuid))
host_uuid_link.allow_tags = True
host_uuid_link.is_safe = True


@register.filter
def uptime_from_seconds(seconds_since_reboot):
  """Converts float seconds_since_reboot to 'N days, hh:mm:ss'."""
  if seconds_since_reboot:
    uptime_days = datetime.timedelta(seconds=seconds_since_reboot).days
    uptime_hms = time.strftime('%H:%M:%S', time.gmtime(seconds_since_reboot))
    return '%d days, %s' % (uptime_days, uptime_hms)
  else:
    return 'unknown'
