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
"""App Engine server module, including classes to handle auth.

Classes:

  Auth1ServerDatastoreSession:  Session storage in datastore for Auth1 classes
  AuthSessionSimianServer:       Session storage for Simian
  AuthSimianServer:              Simian server Auth class

Functions:

  DoMunkiAuth:                  Check Munki client auth credentials.
"""

import Cookie
import datetime
import logging
import os
import time


import webapp2

from google.appengine import runtime
from google.appengine.api import datastore
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.ext import deferred
from google.appengine.runtime import apiproxy_errors

from simian import auth
from simian.auth import base
from simian.auth import util
from simian.mac import models


# Level values supplied to DoMunkiAuth() and used in session data
# Base
LEVEL_APPLESUS = base.LEVEL_APPLESUS
LEVEL_BASE = base.LEVEL_BASE
# Admin
LEVEL_ADMIN = base.LEVEL_ADMIN
# Can upload new/updated packages
LEVEL_UPLOADPKG = LEVEL_ADMIN

ALL_LEVELS = [LEVEL_APPLESUS, LEVEL_BASE, LEVEL_ADMIN, LEVEL_UPLOADPKG]

# Deadline in seconds for datastore RPC operations
DATASTORE_RPC_DEADLINE = 5



class Error(Exception):
  """Base Error."""


class NotAuthenticated(Error, base.NotAuthenticated):
  """Not Authenticated Error."""


class CaParametersError(Error, base.NotAuthenticated):
  """Loading/finding (ca, server certs, keys) error."""


class Auth1ServerDatastoreSession(base.Auth1ServerSession):
  """AuthSession data container which can write to AppEngine datastore."""

  def __init__(self):
    super(Auth1ServerDatastoreSession, self).__init__()
    self.model = self.GetModelClass()
    self.deadline = DATASTORE_RPC_DEADLINE

  @staticmethod
  def GetModelClass():
    """Returns the model class to operate against."""
    raise NotImplementedError

  def _GetConfig(self):
    """Return a config with deadline set.

    Returns:
      google.appengine.api.datastore.UserRPC instance
    """
    config = datastore.CreateRPC(deadline=self.deadline)
    return config

  def _Create(self, sid):
    """Create a session instance and return it.

    Args:
      sid: str, session id
    Returns:
      new session instance datastore entity
    """
    m = self.model(key_name=sid)
    m.data = None
    m.mtime = self._Now()
    return m

  def _Get(self, sid):
    """Get a session instance from storage given its session id.

    Args:
      sid: str, session id
    Returns:
      session instance
    """
    return self.model.get_by_key_name(sid, rpc=self._GetConfig())

  def _Put(self, session):
    """Put a session instance into storage.

    Args:
      session: db.Model, session instance
    """
    session.put(rpc=self._GetConfig())

  def DeleteById(self, sid):
    """Delete session data for a session id.

    Args:
      sid: str, session id
    """
    m = self.model.get_by_key_name(sid, rpc=self._GetConfig())
    if m:
      m.delete(rpc=self._GetConfig())

  def Delete(self, session):
    """Delete one session.

    Args:
      session: db.Model, session instance
    """
    session.delete(rpc=self._GetConfig())

  def All(
      self, min_age_seconds=None, cursor=None, level=None):
    """Iterate through all session entities, yielding each.

    Args:
      min_age_seconds: int seconds of minimum age sessions to return.
      cursor: str starting position.
      level: filter by access level
    Returns:
      Return query.
    """
    q = self.model.all()

    if level is not None:
      q = q.filter('level =', level)

    if min_age_seconds:
      delta = datetime.timedelta(seconds=min_age_seconds)
      min_datetime = datetime.datetime.utcnow() - delta
      q = q.filter('mtime <', min_datetime)

    q.with_cursor(cursor)
    return q

  def GetByUuid(self, uuid):
    return self.model.all().filter('uuid =', uuid).fetch(None)


class Auth1ServerDatastoreMemcacheSession(Auth1ServerDatastoreSession):
  """AuthSession data container which uses memcache as a frontend."""

  def __init__(self):
    super(Auth1ServerDatastoreMemcacheSession, self).__init__()
    self.prefix = 'a1sd_'
    self.ttl = 2 * 60

  def _CallSuperWithDefer(self, method_name, *args, **kwargs):
    """Call a superclass method and defer if a datastore error occurs.

    Args:
      method_name: str, like '_Put'
      *args: optional, args to method
      **kwargs: optional, kwargs to pass to deferred.
    Returns:
      Return from method_name(*args).
    """
    cls = super(Auth1ServerDatastoreMemcacheSession, self)
    method = getattr(cls, method_name)
    try:
      return method(*args)
    except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
      pass  # defer.

    defer_id = '%.0f' % (time.time() * 1000)
    deferred_name = 'a1sdms-%s-%s' % (
        defer_id, method_name.replace('_', ''))
    # logging.debug('Deferring %s %s %s', method_name, args, defer_id)
    deferred.defer(method, _name=deferred_name, *args, **kwargs)

  def _Get(self, sid):
    """Get a session instance from storage given its session id.

    Args:
      sid: str, session id
    Returns:
      session instance
    """
    mcv = memcache.get('%s%s' % (self.prefix, sid))
    if mcv is not None:
      return mcv
    return super(Auth1ServerDatastoreMemcacheSession, self)._Get(sid)

  def _Put(self, session):
    """Put a session instance into storage.

    Args:
      session: db.Model, session instance
    """
    memcache.set(
        '%s%s' % (self.prefix, session.key().name()),
        value=session, time=self.ttl)
    self._CallSuperWithDefer('_Put', session)

  def DeleteById(self, sid):
    """Delete session data for a session id.

    Args:
      sid: str, session id
    """
    memcache.delete('%s%s' % (self.prefix, sid))
    # slightly defer with countdown so that back to back _Put(cn, sn)
    # and DeleteById(cn) are more likely to run in the right order.    best
    # effort, the session cleaner cron will destroy anything leftover later
    # anyway.
    self._CallSuperWithDefer('DeleteById', sid, _countdown=3)

  def Delete(self, session):
    """Delete one session.

    Args:
      session: db.Model, session instance
    """
    memcache.delete('%s%s' % (self.prefix, session.key().name()))
    self._CallSuperWithDefer('Delete', session)


class AuthSessionSimianServer(Auth1ServerDatastoreMemcacheSession):
  """AuthSession data container that uses the Simian AuthSession model."""

  @staticmethod
  def GetModelClass():
    return models.AuthSession

  def IsExpired(self, session, now=None):
    """check whether session is expired."""
    if now is None:
      now = self._Now()
    ek = session.key().name()
    age = None
    if ek.startswith(self.SESSION_TYPE_PREFIX_TOKEN):
      age = datetime.timedelta(seconds=base.AGE_TOKEN_SECONDS)
    elif ek.startswith(self.SESSION_TYPE_PREFIX_CN):
      age = datetime.timedelta(seconds=base.AGE_CN_SECONDS)

    if session.level == LEVEL_APPLESUS:
      age = datetime.timedelta(seconds=base.AGE_APPLESUS_TOKEN_SECONDS)

    if not session.mtime or not age:
      return True

    return now - session.mtime > age


class AuthSimianServer(base.Auth1):
  """Auth1 server which uses AuthSessionSimian for session storage."""

  def __init__(self):
    """TODO(user): remove once certain/done."""
    super(AuthSimianServer, self).__init__()

  def LoadCaParameters(self, settings, ca_id=None):
    """Load ca/cert parameters for CA named ca_id.

    Args:
      settings: object with attribute level access to settings.
      ca_id: str or None (default), identifies the CA/server cert/keys.
    Raises:
      CaParametersError: if any errors occur loading keys/certs for ca_id.
    """
    try:
      ca_params = util.GetCaParameters(settings, ca_id)
    except util.CaParametersError, e:
      raise CaParametersError(*e.args)
    self._ca_pem = ca_params.ca_public_cert_pem
    self._server_cert_pem = ca_params.server_public_cert_pem
    try:
      self.LoadSelfKey(ca_params.server_private_key_pem)
    except ValueError, e:
      raise CaParametersError('server_private_key_pem: %s' % str(e))
    self._required_issuer = ca_params.required_issuer

  def GetSessionClass(self):
    return AuthSessionSimianServer


def DoMunkiAuth(fake_noauth=None, require_level=None):
  """Do Munki auth.

  Args:
    fake_noauth: bool, optional, raise a NotAuthenticated exception
        immediately if True
    require_level: int, optional, require at least this security level in
        token/session data
  Returns:
    models.AuthSession entity that was verified.
  Raises:
    NotAuthenticated: if Auth1 auth has not been supplied
  """
  if fake_noauth:
    raise NotAuthenticated('FakeNoAuth')

  if require_level is None:
    require_level = LEVEL_BASE


  cookie_str = os.environ.get('HTTP_COOKIE', None)
  if not cookie_str:
    logging.info('HTTP_COOKIE is empty or nonexistent.')
    raise NotAuthenticated('NoCookie')

  c = Cookie.SimpleCookie()
  try:
    c.load(cookie_str)
  except TypeError, e:
    logging.info('Cookie could not be loaded, %s: %s', str(e), cookie_str)
    raise NotAuthenticated
  except Cookie.CookieError, e:
    logging.info(
        'Cookie could not be loaded, %s: %s', str(e), cookie_str)
    raise NotAuthenticated('CookieError')

  if (auth.AUTH_TOKEN_COOKIE not in c
      or not c[auth.AUTH_TOKEN_COOKIE]):
    logging.info('Cookie data is empty or does not contain auth token %s',
                 auth.AUTH_TOKEN_COOKIE)
    raise NotAuthenticated('EmptyCookie')

  a = AuthSimianServer()
  token = c[auth.AUTH_TOKEN_COOKIE].value
  try:
    session = a.GetSessionIfAuthOK(token, require_level)
  except base.AuthSessionError as e:
    # If this happens, an auth token is being sent but it's not in
    # memcache/Datastore. It could be that clients are sleeping during Munki
    # executions, thus when they wake and Munki continues their session is
    # expired and deleted. Or it could be some bug with saving and accessing
    # sessions.
    logging.info('DoMunkiAuth: %s', str(e))
    raise NotAuthenticated('UnknownAuthToken')

  # logging.debug('Auth client connected: uuid %s', session.uuid)

  return session


def LogoutSession(session):
  """Logs out of a given session.

  Args:
    session: db.Model, session instance
  """
  a = AuthSessionSimianServer()
  try:
    a.Delete(session)
  except (db.Error, apiproxy_errors.Error, runtime.DeadlineExceededError):
    deferred_name = 'logout-%.0f' % (time.time() * 1000)
    deferred.defer(LogoutSession, session, _name=deferred_name, _countdown=60)
