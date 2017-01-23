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
"""Module for sending e-mails."""

import logging

from google.appengine.api import mail as mail_tool
from google.appengine.api import taskqueue
from google.appengine.ext import deferred
from google.appengine.runtime import apiproxy_errors
# circular dependency. settings module is not used during initialization.
import simian.settings


def _SendMailDeferCallback(message):
  try:
    message.send()
  except mail_tool.Error:
    logging.exception('Error deferring email.')


def SendMail(recipient, subject, body, defer=True):
  try:
    message = mail_tool.EmailMessage(
        to=recipient, sender=simian.settings.EMAIL_SENDER,
        subject=subject, body=body)
  except (mail_tool.InvalidEmailError, mail_tool.InvalidSenderError):
    logging.exception(
        'Error sendinge email; verify email related configurations.')
  else:
    try:
      if defer:
        deferred.defer(_SendMailDeferCallback, message)
      else:
        _SendMailDeferCallback(message)
    except (deferred.Error, taskqueue.Error, apiproxy_errors.Error):
      logging.exception('Error deferring email.')
