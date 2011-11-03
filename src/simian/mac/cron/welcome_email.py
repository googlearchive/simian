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

"""Module containing url handler for welcome email cron.

Classes:
  WelcomeEmail: the url handler
"""



import datetime
import logging
import os
import re
from google.appengine.api import mail
from google.appengine.api import memcache
from google.appengine.ext import webapp
from google.appengine.runtime import apiproxy_errors
from simian import settings
from simian.mac import models


CLIENTS_PER_EXECUTION = 500


class WelcomeEmail(webapp.RequestHandler):
  """Class to send welcome emails to new clients."""

  def get(self):
    """Handle GET"""
    if not settings.SEND_WELCOME_EMAILS:
      return

    office_launch = {}
    office_query = models.OfficeLaunch.all()
    for office in office_query:
      if office.enabled:  # only include enabled offices.
        office_launch[office.site] = office.regex

    clients_count = 0
    query = models.FirstClientConnection.all().filter('emailed =', None)
    cursor = memcache.get('welcome_email_cursor')
    if cursor:
      query.with_cursor(cursor)
      memcache.delete('welcome_email_cursor')

    computers = query.fetch(100)
    while computers:
      for c in computers:
        # Bypass disabled sites/offices.
        regex = office_launch.get(c.site, None)
        if not regex or not re.search(regex, c.office, re.IGNORECASE):
          continue
        owner_email = '%s@%s' % (c.owner, settings.EMAIL_DOMAIN)
        #logging.debug('Sending welcome email to %s.', owner_email)
        # Email the user.
        m = mail.EmailMessage()
        m.body = settings.WELCOME_EMAIL_BODY % {
            'owner': c.owner, 'hostname': c.hostname}
        m.reply_to = settings.EMAIL_REPLY_TO
        m.sender = settings.EMAIL_SENDER
        try:
          m.subject = settings.WELCOME_EMAIL_SUBJECT % c.hostname
        except TypeError:
          # admin omitted %s in the subject config, so just set static subject.
          m.subject = settings.WELCOME_EMAIL_SUBJECT
        m.to = owner_email
        try:
          m.send()
        except apiproxy_errors.DeadlineExceededError:
          #logging.info('Email failed to send; skipping.')
          continue
        # Update the WelcomeEmail entity so no further emails are sent.
        c.emailed = datetime.datetime.utcnow()
        c.put()
        clients_count += 1
      if clients_count >= CLIENTS_PER_EXECUTION:
        break
      query.with_cursor(query.cursor())
      computers = query.fetch(100)

    if computers:
      memcache.set('welcome_email_cursor', query.cursor())
    else:
      memcache.delete('welcome_email_cursor')