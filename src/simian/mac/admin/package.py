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
"""Package admin handler."""

import datetime
import httplib
import urllib

from google.appengine.api import app_identity
from google.appengine.api import users

from simian import settings
from simian.mac import admin
from simian.mac import common
from simian.mac import models
from simian.mac.admin import xsrf
from simian.mac.common import auth

try:
  from simian.mac.common import mail
except ImportError:
  mail = None




class Package(admin.AdminHandler):
  """Handler for /admin/package."""

  def get(self, filename=None):
    """GET handler."""
    if not filename:
      self.error(httplib.NOT_FOUND)
      return
    elif not auth.HasPermission(auth.VIEW_PACKAGES):
      self.error(httplib.FORBIDDEN)
      return

    filename = urllib.unquote(filename)
    p = models.PackageInfo.get_by_key_name(filename)
    if not p:
      self.error(httplib.NOT_FOUND)
      self.Render(
          'error.html', {'message': 'PackageInfo not found: %s' % filename})
      return

    p.name = p.plist['name']
    p.display_name = p.plist.get('display_name', '')
    p.unattended = p.plist.get('unattended_install')
    p.unattended_uninstall = p.plist.get('unattended_uninstall')
    p.version = p.plist['version']
    force_install_after_date = p.plist.get('force_install_after_date', None)
    if force_install_after_date:
      p.force_install_after_date = datetime.datetime.strftime(
          force_install_after_date, '%Y-%m-%d')
      p.force_install_after_date_time = datetime.datetime.strftime(
          force_install_after_date, '%H:%M')

    if self.request.referrer and self.request.referrer.endswith('proposals'):
      return_address = '/admin/proposals'
      return_title = 'proposals'
    else:
      return_address = '/admin/packages'
      return_title = 'package'

    if self.request.get('plist_xml'):
      self.Render('plist.html',
                  {'report_type': 'packages',
                   'plist_type': 'package_plist',
                   'xml': admin.XmlToHtml(p.plist.GetXml()),
                   'title': 'Plist for %s' % p.name,
                   'raw_xml_link': '/pkgsinfo/%s' % filename,
                  })
    else:
      categories = (
          [x.strip() for x in settings.LIST_OF_CATEGORIES.split(',') if x])
      manifests_and_catalogs_unlocked = (
          p.blob_info or p.plist.get('PackageCompleteURL'))
      data = {
          'pkg': p,
          'report_type': 'package',
          'tracks': common.TRACKS,
          'install_types': common.INSTALL_TYPES,
          'manifest_mod_groups': common.MANIFEST_MOD_GROUPS,
          'approval_required': settings.APPROVAL_REQUIRED,
          'is_admin_user': self.IsAdminUser(),
          'is_support_user': auth.IsSupportUser(),
          'pkg_safe_to_modify': p.IsSafeToModify(),
          'editxml': self.request.get('editxml'),
          'manifests_and_catalogs_unlocked': manifests_and_catalogs_unlocked,
          'return_address': return_address,
          'return_title': return_title,
          'categories': categories}

      self.Render('package.html', data)

  def post(self, filename=None):
    """POST handler."""
    if not auth.HasPermission(auth.UPLOAD):
      self.error(httplib.FORBIDDEN)
      self.response.out.write('Access Denied for current user')
      return

    xsrf_token = self.request.get('xsrf_token', None)
    report_type = filename and 'package' or 'packages'
    if not xsrf.XsrfTokenValidate(xsrf_token, report_type):
      self.error(httplib.BAD_REQUEST)
      self.Render(
          'error.html',
          {'message': 'Invalid XSRF token. Please refresh and retry.'})
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
        self.error(httplib.NOT_FOUND)
        self.Render(
            'error.html', {'message': 'PackageInfo not found: %s' % filename})
        return

      if self.request.get('delete') == '1':
        self._DeletePackage(p, filename)

      elif self.request.get('submit', None) == 'save':
        self.UpdatePackageInfo(p)

      elif self.request.get('unlock') == '1':
        self._UnlockPackage(p, filename)

      elif self.request.get('approve') == '1':
        if p.proposal.proposal_in_flight:
          self._ApproveProposal(p, filename)

      elif self.request.get('reject') == '1':
        if p.proposal.proposal_in_flight:
          self._RejectProposal(p, filename)

      else:
        self.error(httplib.BAD_REQUEST)
        self.Render(
            'error.html', {'message': 'No action specified or unknown action.'})

    elif self.request.get('new_pkginfo_plist'):
      # No filename was specified, so we're creating a new PackageInfo.
      self.UpdatePackageInfoFromPlist(create_new=True)
    else:
      self.error(httplib.NOT_FOUND)

  def _ApproveProposal(self, p, filename):
    if not self.IsAdminUser():
      self.redirect(
          '/admin/package/%s?msg=Only admins can approve proposals' % (
              filename))
    else:
      try:
        p.proposal.ApproveProposal()
        self.redirect(
            '/admin/package/%s?msg=Changes approved for %s' % (
                filename, filename))
      except models.PackageInfoProposalApprovalError:
        self.redirect(
            '/admin/package/%s?msg=Unable to approve changes to %s' % (
                filename, filename))
      except models.PackageInfoLockError:
        self.redirect(
            '/admin/package/%s?msg=Unable to approve changes, package '
            'is locked.' % (filename))
      except models.PackageInfoUpdateError:
        self.redirect(
            '/admin/package/%s?msg=Unable to approve changes, a package '
            'with the same name already in catalog.' % (filename))

  def _DeletePackage(self, p, filename):
    if not self.IsAdminUser():
      self.redirect(
          '/admin/package/%s?msg=Only admins can delete packages' % (filename))
    else:
      if p.IsSafeToModify():
        if settings.EMAIL_ON_EVERY_CHANGE:
          self.NotifyAdminsOfPackageDeletion(p)
        p.delete()
        self.redirect(
            '/admin/packages?msg=%s successfully deleted' % filename)
      else:
        self.redirect(
            '/admin/package/%s?msg=Unlock package before deleting.')

  def _RejectProposal(self, p, filename):
    if not self.IsAdminUser():
      self.redirect('/admin/package/%s?msg=Only admins can reject '
                    'proposals' % (filename))
    else:
      p.proposal.RejectProposal()
      self.redirect(
          '/admin/package/%s?msg=Changes rejected for %s' % (
              filename, filename))

  def _UnlockPackage(self, p, filename):
    if not self.IsAdminUser():
      self.redirect('/admin/package/%s?msg=Only admins are allowed to '
                    'unlock packages.' % (filename))
    else:
      if settings.EMAIL_ON_EVERY_CHANGE:
        self.NotifyAdminsOfPackageUnlock(p)
      p.MakeSafeToModify()
      self.redirect(
          '/admin/package/%s?msg=%s is safe to modify' % (
              filename, filename))

  def NotifyAdminsOfPackageChange(self, pkginfo, **kwargs):
    """Notifies admins of changes to packages."""
    subject_line = 'MSU Package Update by %s - %s' % (users.get_current_user(),
                                                      pkginfo.filename)
    main_body = ['New configuration:\n']
    for key, value in kwargs.iteritems():
      if key == 'manifests':
        if pkginfo.manifests != value:
          main_body.append('Manifests: %s --> %s' % (
              ', '.join(pkginfo.manifests), ', '.join(value)))
      elif key == 'catalogs':
        if pkginfo.catalogs != value:
          main_body.append('Catalogs: %s --> %s' % (
              ', '.join(pkginfo.catalogs), ', '.join(value)))
      elif key == 'install_types':
        if pkginfo.install_types != value:
          main_body.append('Install Types: %s --> %s' % (
              ', '.join(pkginfo.install_types), ', '.join(value)))
      elif key == 'munki_name':
        if pkginfo.munki_name != value:
          main_body.append('Munki Name: %s --> %s' % (
              pkginfo.munki_name, value))
      elif (key == 'force_install_after_date'
            and pkginfo.plist.get(key, '') != value):
        main_body.append('%s: %s' % (key, value))
      elif type(value) is list:
        if pkginfo.plist.get(key, []) != value:
          main_body.append('%s: %s --> %s' % (
              key, ', '.join(pkginfo.plist.get(key, [])), ', '.join(value)))
      else:
        if pkginfo.plist.get(key, '') != value:
          main_body.append(
              '%s: %s --> %s' % (key, pkginfo.plist.get(key, ''), value))
    if mail:
      mail.SendMail(
          settings.EMAIL_ADMIN_LIST, subject_line, '\n'.join(main_body))

  def NotifyAdminsOfPackageChangeFromPlist(self, log, defer=True):
    """Notifies admins of changes to packages."""
    subject_line = 'MSU Package Update by %s - %s' % (
        users.get_current_user(), log.filename)

    plist_diff = log.plist_diff
    main_body = 'Diff:\n' + '\n'.join([x['line'] for x in plist_diff])
    if mail:
      mail.SendMail(
          settings.EMAIL_ADMIN_LIST, subject_line, main_body, defer=defer)

  def NotifyAdminsOfPackageDeletion(self, pkginfo):
    """Notifies admins of packages deletions."""
    subject_line = 'MSU Package Deleted by %s - %s' % (users.get_current_user(),
                                                       pkginfo.filename)
    main_body = 'That package has been deleted, hope you didn\'t need it.'
    if mail:
      mail.SendMail(settings.EMAIL_ADMIN_LIST, subject_line, main_body)

  def NotifyAdminsOfPackageUnlock(self, pkginfo):
    """Notifies admins of package being unlocked."""
    subject_line = 'MSU Package Unlocked by %s - %s' % (
        users.get_current_user(), pkginfo.filename)
    main_body = 'That package has been removed from all catalogs and manifests.'
    if mail:
      mail.SendMail(settings.EMAIL_ADMIN_LIST, subject_line, main_body)

  def UpdatePackageInfo(self, pkginfo):
    """Updates an existing PackageInfo entity."""
    unattended_install = self.request.get('unattended_install', None)
    if unattended_install is not None:
      unattended_install = unattended_install == 'on'

    unattended_uninstall = self.request.get('unattended_uninstall', None)
    if unattended_uninstall is not None:
      unattended_uninstall = unattended_uninstall == 'on'

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
        self.error(httplib.BAD_REQUEST)
        self.Render(
            'error.html',
            {'message': 'invalid force_install date and/or time format'})
    else:
      # This will remove force_install_after_date from the plist, as it was
      # unset in the UI.
      force_install_after_date = ''

    kwargs = {
        'unattended_install': unattended_install,
        'unattended_uninstall': unattended_uninstall,
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
        'category': self.request.get('category', None),
        'developer': self.request.get('developer', None),
    }
    try:
      pkginfo.Update(**kwargs)
      if settings.EMAIL_ON_EVERY_CHANGE:
        self.NotifyAdminsOfPackageChange(pkginfo, **kwargs)
    except models.PackageInfoLockError:
      self.error(httplib.FOUND)
      self.Render(
          'error.html',
          {'message': 'PackageInfo was locked; refresh and try again'})
    except models.PackageInfoUpdateError as e:
      self.error(httplib.FORBIDDEN)
      self.Render(
          'error.html', {'message': 'PackageInfoUpdateError: %s' % str(e)})
    else:
      filename = pkginfo.filename
      self.redirect(
          '/admin/packages?msg=%s saved.&activepkg=%s#package-%s' % (
              filename, filename, filename))

  def UpdatePackageInfoFromPlist(self, create_new=False):
    """Updates or creates a new PackageInfo entity from plist XML."""
    plist_xml = self.request.get('new_pkginfo_plist').encode('utf-8').strip()
    try:
      pkginfo, log = models.PackageInfo.UpdateFromPlist(
          plist_xml, create_new=create_new)
    except models.PackageInfoUpdateError as e:
      self.error(httplib.BAD_REQUEST)
      self.Render(
          'error.html', {'message': 'PackageInfoUpdateError: %s' % str(e)})
      return
    else:
      if settings.email_on_every_change:
        self.NotifyAdminsOfPackageChangeFromPlist(log)

    self.redirect('/admin/package/%s?msg=PackageInfo saved#package-%s' % (
        pkginfo.filename, pkginfo.filename))
