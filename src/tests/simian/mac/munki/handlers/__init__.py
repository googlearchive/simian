#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
#

"""Top level __init__ for handlers package."""



import datetime
import logging
import os
import sys
import traceback
import urllib
from simian.auth import base as _auth_base
from simian.mac.munki import common


HEADER_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'


class Error(Exception):
  """Base Error."""


def IsHttps(rh=None):
  """Check for https in request connection.

  If not https, setup a redirect to the https page.

  Args:
    rh: webapp.RequestHandler, optional, to set redirect() on
  Returns:
    False if the current connection is not HTTPS
    True if the current connection is HTTPS
  Raises:
    Error: if rh is specified and a URL to redirect to cannot be determined
  """
  if os.environ.get('HTTPS', None) == 'on':
    return True

  if rh is not None:
    if not os.environ.get('SERVER_NAME', None):
      raise Error('Cannot determine current site URL')

    rh.redirect('https://%s%s' % (
        os.environ['SERVER_NAME'],
        os.environ.get('PATH_INFO', '/'))
        )

  return False


def IsBlobstore():
  """Check if Blobstore is the request connection source.

  Or, if this is a dev_appserver instance, pretend that it's Blobstore.

  Returns:
    True if it is,
    False if it is not
  """
  # to explain the following logic, see the following doc for production:
  #
  # 0.1.0.30 is the impersonated address for BlobStore/Scotty backend.
  #
  # for dev_appserver, when handling an upload, after blob handling
  # the appserver re-POSTs to the handler URL.  the entire post has
  # been reformulated with new MIME boundaries etc, and the User Agent
  # has been lost.
  #
  return os.environ.get('REMOTE_ADDR', None) == '0.1.0.30' or (
     os.environ.get('SERVER_SOFTWARE', '').startswith('Development') and
     os.environ.get('HTTP_USER_AGENT', None) is None)


def StrHeaderDateToDatetime(str_header_dt):
  """Converts a string header date to a datetime object.

  Args:
    str_header_dt: str date from header, i.e. If-Modified-Since.
  Returns:
    datetime.datetime object, or None if there's a parsing error.
  """
  if not str_header_dt:
    return
  try:
    # NOTE(user): strptime is a py2.5+ feature.
    return datetime.datetime.strptime(str_header_dt, HEADER_DATE_FORMAT)
  except ValueError:
    logging.exception(
        'Error parsing If-Modified-Since date: %s', str_header_dt)


def IsClientResourceExpired(resource_dt, str_header_dt):
  """Compares an If-Modified-Since header date to a passed datetime.

  Args:
    resource_dt: datetime to use for comparison.
    str_header_dt: str date value like "Wed, 06 Oct 2010 03:23:34 GMT".
  Returns:
    Boolean. True if client resource requires an update due to unmatched dates.
  """
  header_dt = StrHeaderDateToDatetime(str_header_dt)
  if not header_dt:
    return True

  # if datetime and header date are the same (disregarding ms) then not modified
  if resource_dt.replace(microsecond=0) == header_dt:
    return False
  else:
    return True


def GetClientIdForRequest(request, session=None, client_id_str=None):
  """Returns a client_id dict for the given request.

  Args:
    request: webapp Request object.
    session: response from auth.DoAnyAuth().
    client_id_str: str client id.
  Returns:
    a dict client_id.
  """
  if hasattr(session, 'uuid'):  # DoMunkiAuth returned session, override uuid
    # webapp's request.headers.get() returns None if the key doesn't exist
    # which breaks urllib.unquote(), so return empty string default instead.
    client_id = request.headers.get('X-munki-client-id', '')
    if not client_id:
      logging.warning('Client ID header missing: %s', session.uuid)
    client_id = urllib.unquote(client_id)
    client_id = common.ParseClientId(client_id, uuid=session.uuid)
  else:  # DoUserAuth was called; setup client id
    client_id_str = urllib.unquote(client_id_str)
    client_id = common.ParseClientId(client_id_str)

  return client_id


class AuthenticationHandler(object):
  """Class which handles NotAuthenticated exceptions."""

  def handle_exception(self, exception, debug_mode):
    """Handle an exception.

    Args:
      exception: exception that was thrown
      debug_mode: True if the application is running in debug mode
    """
    if issubclass(exception.__class__, _auth_base.NotAuthenticated):
      exc_type, exc_value, exc_tb = sys.exc_info()
      tb = traceback.format_exception(exc_type, exc_value, exc_tb)
      logging.warning('handle_exception: %s', ''.join(tb))
      self.error(403)
      return

    super(AuthenticationHandler, self).handle_exception(exception, debug_mode)
