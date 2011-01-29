#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
#

"""Top level __init__ for handlers package."""



import os
from simian.auth import base as _auth_base


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


class AuthenticationHandler(object):
  """Class which handles NotAuthenticated exceptions."""

  def handle_exception(self, exception, debug_mode):
    """Handle an exception.

    Args:
      exception: exception that was thrown
      debug_mode: True if the application is running in debug mode
    """
    if issubclass(exception.__class__, _auth_base.NotAuthenticated):
      self.error(403)
      return

    super(AuthenticationHandler, self).handle_exception(
        exception, debug_mode)
