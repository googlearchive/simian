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
"""UploadFile URL handlers."""

import httplib
import logging

from google.appengine.ext import deferred
from google.appengine.runtime import apiproxy_errors

from simian import settings
from simian.auth import gaeserver
from simian.mac import common as main_common
from simian.mac import models
from simian.mac.common import mail
from simian.mac.munki import handlers


class UploadFile(handlers.AuthenticationHandler):
  """Handler for /uploadfile."""

  def put(self, file_type=None, file_name=None):
    """UploadFile PUT handler.

    Returns:
      A webapp.Response() response.
    """
    session = gaeserver.DoMunkiAuth()
    uuid = main_common.SanitizeUUID(session.uuid)

    if not file_type or not file_name:
      logging.warning('file_type=%s , file_name=%s', file_type, file_name)
      self.error(httplib.NOT_FOUND)
      return

    if file_type == 'log':
      key = '%s_%s' % (uuid, file_name)
      l = models.ClientLogFile(key_name=key)
      l.log_file = self.request.body
      l.uuid = uuid
      l.name = file_name
      try:
        l.put()
      except apiproxy_errors.RequestTooLargeError:
        logging.warning('UploadFile log too large; truncating...')
        # Datastore has a 1MB entity limit and models.ClientLogFile.log_file
        # uses zlib compression. Anecdotal evidence of a handlful of log files
        # over 8MB in size compress down to well under 1MB. Therefore, slice
        # the top of the log data off at a conversative max, before retrying the
        # Datastore put.
        max_log_size_bytes = 5 * 1024 * 1024
        l.log_file = ('*** Log truncated by Simian due to size ***\n\n' +
                      self.request.body[-1 * max_log_size_bytes:])
        l.put()

      c = models.Computer.get_by_key_name(uuid)
      recipients = c.upload_logs_and_notify
      c.upload_logs_and_notify = None
      c.put()

      # c.upload_logs_and_notify may be None from a previous upload, as multiple
      # files may be uploaded in different requests per execution.
      if recipients:
        recipients = recipients.split(',')
        deferred.defer(
            SendNotificationEmail, recipients, c, settings.SERVER_HOSTNAME)
    else:
      self.error(httplib.NOT_FOUND)


def SendNotificationEmail(recipients, c, server_fqdn):
  """Sends a log upload notification email to passed recipients.

  Args:
    recipients: list, str email addresses to email.
    c: models.Computer entity.
    server_fqdn: str, fully qualified domain name of the server.
  """
  body = []
  body.append('https://%s/admin/host/%s\n' % (server_fqdn, c.uuid))
  body.append('Owner: %s' % c.owner)
  body.append('Hostname: %s' % c.hostname)
  body.append('Client Version: %s' % c.client_version)
  body.append('OS Version: %s' % c.os_version)
  body.append('Site: %s' % c.site)
  body.append('Track / Config Track: %s / %s' % (c.track, c.config_track))
  body.append('Serial Number: %s' % c.serial)
  body.append('Last preflight: %s' % c.preflight_datetime)
  body.append('Last postflight: %s' % c.postflight_datetime)
  body.append(('Preflight count since postflight: %s' %
               c.preflight_count_since_postflight))
  body = '\n'.join(body)
  subject = 'Logs you requested have been uploaded for %s' % c.hostname

  mail.SendMail(recipients, subject, body)
