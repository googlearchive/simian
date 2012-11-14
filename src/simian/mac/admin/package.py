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

"""Package admin handler."""




import datetime
import urllib

from google.appengine.api import users

from simian.mac import admin
from simian.mac import models
from simian.mac import common
from simian.mac.admin import xsrf
from simian.mac.common import gae_util
from simian.mac.munki import common as munki_common
from simian.mac.munki import plist as plist_lib


class Package(admin.AdminHandler):
  """Handler for /admin/package."""

  XSRF_PROTECT = True

  def get(self, filename=None):
    """GET handler."""
    if not self.IsAdminUser() or not filename:
      self.error(404)
      return

    filename = urllib.unquote(filename)
    p = models.PackageInfo.get_by_key_name(filename)
    if not p:
      self.error(404)
      self.response.out.write('PackageInfo not found: %s' % filename)
      return

    p.name = p.plist['name']
    p.display_name = p.plist.get('display_name', '')
    p.unattended = p.plist.get('unattended_install')
    p.version = p.plist['version']
    force_install_after_date = p.plist.get('force_install_after_date', None)
    if force_install_after_date:
      p.force_install_after_date = datetime.datetime.strftime(
              force_install_after_date, '%Y-%m-%d')
      p.force_install_after_date_time = datetime.datetime.strftime(
              force_install_after_date, '%H:%M')

    if self.request.get('plist_xml'):
      self.Render('plist.html',
          {'report_type': 'packages',
           'plist_type': 'package_plist',
           'xml': admin.XmlToHtml(p.plist.GetXml()),
           'title': "Plist for %s" % p.name,
           'raw_xml_link': "/pkgsinfo/%s" % filename,
           })
    else:
      manifests_and_catalogs_unlocked = (
          p.blob_info or p.plist.get('PackageCompleteURL'))
      data = {
          'pkg': p, 'report_type': 'package', 'tracks': common.TRACKS,
          'install_types': common.INSTALL_TYPES,
          'manifest_mod_groups': common.MANIFEST_MOD_GROUPS,
          'pkg_safe_to_modify': p.IsSafeToModify(),
          'editxml': self.request.get('editxml'),
          'manifests_and_catalogs_unlocked': manifests_and_catalogs_unlocked}

      self.Render('package.html', data)

  def post(self, filename=None):
    """POST handler."""
    if not self.IsAdminUser():
      self.error(403)
      self.response.out.write('Access Denied for current user')
      return

    xsrf_token = self.request.get('xsrf_token', None)
    report_type = filename and 'package' or 'packages'
    if not xsrf.XsrfTokenValidate(xsrf_token, report_type):
      self.error(400)
      self.response.out.write("Invalid XSRF token. Please refresh and retry.")
      return

    if filename:
      filename = urllib.unquote(filename)

      # If we're updating from new plist xml, perform the update and return.
      if self.request.get('new_pkginfo_plist'):
        self.UpdatePackageInfoFromPlist()
        return

      # All non-plist updates require an existing PackageInfo entity.
      p = models.PackageInfo.get_by_key_name(filename)
      if not p:
        self.error(404)
        self.response.out.write('Filename not found: %s' % filename)
        return

      if self.request.get('delete') == '1':
        p.delete()
        self.redirect('/admin/packages?msg=%s successfully deleted' % filename)
        return
      elif self.request.get('submit', None) == 'save':
        self.UpdatePackageInfo(p)
      elif self.request.get('unlock') == '1':
        p.MakeSafeToModify()
        self.redirect(
            '/admin/package/%s?msg=%s is safe to modify' % (filename, filename))
      else:
        self.error(400)
        self.response.out.write('No action specified or unknown action.')

    elif self.request.get('new_pkginfo_plist'):
      # No filename was specified, so we're creating a new PackageInfo.
      self.UpdatePackageInfoFromPlist(create_new=True)
    else:
      self.error(404)

  def UpdatePackageInfo(self, pkginfo):
    """Updates an existing PackageInfo entity."""
    unattended_install = self.request.get('unattended_install', None)
    if unattended_install is not None:
      unattended_install = unattended_install == 'on'

    # Parse any force_install_after_date str into a datetime object.
    force_install_after_date_str = self.request.get(
        'force_install_after_date', None)
    force_install_after_date_time_str = self.request.get(
        'force_install_after_date_time', None)
    if force_install_after_date_str or force_install_after_date_time_str:
      date_string = '%s %s' % (
          force_install_after_date_str, force_install_after_date_time_str)
      try:
        force_install_after_date = datetime.datetime.strptime(
            date_string, '%Y-%m-%d %H:%M')
      except ValueError:
        self.error(400)
        self.response.out.write('invalid force_install date and/or time format')
        return
    else:
      # This will remove force_install_after_date from the plist, as it was
      # unset in the UI.
      force_install_after_date = ''

    kwargs = {
        'unattended_install': unattended_install,
        # get_all() returns an empty array if set, and has no default value opt.
        'catalogs': self.request.get_all('catalogs'),
        'manifests': self.request.get_all('manifests'),
        'install_types': self.request.get_all('install_types'),
        'manifest_mod_access': self.request.get_all('manifest_mod_access'),
        # get() returns an empty string if not set, so default to None.
        'name': self.request.get('name', None),
        'description': self.request.get('description', None),
        'display_name': self.request.get('display_name', None),
        'version': self.request.get('version', None),
        'minimum_os_version': self.request.get('minimum_os_version', None),
        'maximum_os_version': self.request.get('maximum_os_version', None),
        'force_install_after_date': force_install_after_date,
    }
    try:
      pkginfo.Update(**kwargs)
    except models.PackageInfoLockError:
      self.error(302)
      self.response.out.write('PackageInfo was locked; refresh and try again')
    except models.PackageInfoUpdateError, e:
      self.error(403)
      self.response.out.write('PacakgeInfoUpdateError: %s' % str(e))
    else:
      filename = pkginfo.filename
      self.redirect(
          '/admin/packages?msg=%s saved.&activepkg=%s#package-%s' % (
              filename, filename, filename))

  def UpdatePackageInfoFromPlist(self, create_new=False):
    """Updates or creates a new PackageInfo entity from plist XML."""
    plist_xml = self.request.get('new_pkginfo_plist').encode('utf-8').strip()
    try:
      pkginfo = models.PackageInfo.UpdateFromPlist(
          plist_xml, create_new=create_new)
    except models.PackageInfoUpdateError, e:
      self.error(400)
      self.response.out.write('PackageInfo Error: %s' % str(e))
      return

    self.redirect('/admin/package/%s?msg=PackageInfo saved#package-%s' % (
        pkginfo.filename, pkginfo.filename))