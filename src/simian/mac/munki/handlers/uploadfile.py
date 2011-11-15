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

"""UploadFile URL handlers."""



import datetime
import logging
import os
import re
import time
import urllib
from google.appengine.ext import webapp
from google.appengine.ext import deferred
from google.appengine.api import mail
from simian import settings
from simian.auth import gaeserver
from simian.mac import models
from simian.mac import common as main_common
from simian.mac.munki import handlers


class UploadFile(handlers.AuthenticationHandler, webapp.RequestHandler):
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
      self.error(404)
      return

    if file_type == 'log':
      key = '%s_%s' % (uuid, file_name)
      l = models.ClientLogFile(key_name=key)
      l.log_file = self.request.body
      l.uuid = uuid
      l.name = file_name
      l.put()

      c = models.Computer.get_by_key_name(uuid)
      recipients = c.upload_logs_and_notify
      c.upload_logs_and_notify = None
      c.put()

      # c.upload_logs_and_notify may be None from a previous upload, as multiple
      # files may be uploaded in different requests per execution.
      if recipients:
        recipients = recipients.split(',')
        deferred.defer(SendNotificationEmail, recipients, c)
    else:
      self.error(404)


def SendNotificationEmail(recipients, c):
  """Sends a log upload notification email to passed recipients.

  Args:
    recipients: list, str email addresses to email.
    c: models.Computer entity.
  """
  body = []
  body.append('https://%s/admin/host/%s\n' % (settings.SERVER_HOSTNAME, c.uuid))
  body.append('Owner: %s' % c.owner)
  body.append('Hostname: %s' % c.hostname)
  body.append('Client Version: %s' % c.client_version)
  body.append('OS Version: %s' % c.os_version)
  body.append('Site / Office: %s / %s' % (c.site, c.office))
  body.append('Track / Config Track: %s / %s' % (c.track, c.config_track))
  body.append('Serial Number: %s' % c.serial)
  body.append('Last postflight: %s' % c.postflight_datetime)
  body = '\n'.join(body)
  subject = 'Logs you requested have been uploaded for %s' % c.hostname
  message = mail.EmailMessage(
      to=recipients, sender=settings.EMAIL_SENDER, subject=subject,
      body=body)
  message.send()