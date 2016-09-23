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
"""Handles authentication and authorization with Munki clients.

Classes:

  AuthBase:    base class
  Auth1:       implementation of Munki/Simian auth, server side
  Auth1Client: implementation of Munki/Simian, client side

  AuthSessionBase:    base class to store session details
  AuthSessionDict:    session storage in a dict
  Auth1ServerSession: session storage for Auth1 server
  Auth1ClientSession: session storage for Auth1 client

"""

import warnings
warnings.filterwarnings(
    'ignore', '.* sha module .*', DeprecationWarning, '.*', 0)

import array  # (Mute warnings before cause) pylint: disable=g-bad-import-order,g-import-not-at-top
import base64
import datetime
import logging
import os
import struct


from simian.auth import tlslite_bridge
from simian.auth import x509

# Message separator
MSG_SEP = ' '
# Valid age of authentication tokens, in seconds
AGE_TOKEN_SECONDS = 6 * 60 * 60
# Valid age of Cn / Sn pair data, in seconds
AGE_CN_SECONDS = 5 * 60
# Valid age of any other default session data
AGE_DEFAULT_SECONDS = 6 * 60 * 60
AGE_APPLESUS_TOKEN_SECONDS = 14 * 24 * 60 * 60
# Minimum value for Cn (client nonce) value
MIN_VALUE_CN = 2**100

# Level values supplied to DoMunkiAuth() and used in session data
LEVEL_APPLESUS = -5
LEVEL_BASE = 0
LEVEL_ADMIN = 5


class Error(Exception):
  """Base."""


class NotAuthenticated(Error):
  """Not authenticated."""

  def __init__(self, reason='Unknown'):
    self.reason = reason
    super(NotAuthenticated, self).__init__()


class AuthSessionError(Error):
  """There is a problem with the auth session."""


class KeyNotLoaded(Error):
  """A key is needed to complete this operation, but none has been loaded."""


class CertificateParseError(Error):
  """Error in parsing an X509 certificate."""


class CertificateError(Error):
  """Error in accepting the details the X509 certificate presents."""


class MessageError(Error):
  """Error in the format of a message."""


class SessionDataError(Error):
  """Session data is malformed."""


class CryptoError(Error):
  """Low level error in crypto libraries."""


class State(object):
  """States of a BaseAuth class."""

  # Waiting for nothing
  NONE = 'NONE'
  # Waiting for input via Input()
  INPUT = 'INPUT'
  # Waiting to output via Output()
  OUTPUT = 'OUTPUT'


class AuthState(object):
  """Authentication states of a BaseAuth class."""

  # Authentication has not yet been determined.
  UNKNOWN = 'UNKNOWN'
  # Authentication passed with details supplied, nothing further needed.
  OK = 'OK'
  # Authentication failed with details supplied.
  FAIL = 'FAIL'


class AuthSessionBase(object):
  """Base class for AuthSession session storage objects.

  This class has no underlying storage mechanism and so raises
  NotImplementedError for all actions.

  _Create, _Get, _Put, DeleteById, Delete should be overriden in subclasses.
  """

  def _Create(self, sid):
    """Create a session instance and return it.

    Args:
      sid: str, session id
    Returns:
      new session instance
    """
    raise NotImplementedError

  def _Get(self, sid):
    """Get a session instance from storage given its session id.

    Args:
      sid: str, session id
    Returns:
      session instance
    """
    raise NotImplementedError

  def _Put(self, session):
    """Put a session instance into storage.

    Args:
      session: obj, session instance
    """
    raise NotImplementedError

  def Set(self, sid, data=None, **kwargs):
    """Set session data.

    Args:
      sid: str, session id
      data: str, optional, data to set
      kwargs: dict, optional, other properties to set on session
    """
    session = self._Create(sid)
    session.data = data
    if kwargs:
      for k in kwargs:
        if k not in ['sid', 'mtime']:
          setattr(session, k, kwargs[k])
    self._Put(session)

  def Get(self, sid):
    """Get session data.

    Args:
      sid: str, session id
    Returns:
      None if no session with that session id exists, OR
      value of 'data' property if session contains it and it is not None, OR
      entire session property if session contains multiple values
    """
    session = self._Get(sid)
    if session:
      if not self.ExpireOne(session):
        if session.data is not None:
          return session.data
        else:
          return session

  def DeleteById(self, sid):
    """Delete session data for a session id.

    Args:
      sid: str, session id
    """
    raise NotImplementedError

  def _Now(self):
    """Return the current time in UTC.

    Returns:
      datetime.datetime in UTC timezone
    """
    now = datetime.datetime.utcnow()
    return now

  def _Mtime(self, session):
    """Return the mtime, last modified time, of a session object.

    Args:
      session: obj, session instance
    Returns:
      datetime.datetime, mtime in UTC
    """
    return session.mtime

  def Delete(self, session):
    """Delete one session.

    Args:
      session: obj, session instance
    """
    raise NotImplementedError

  def All(self, min_age_seconds=None):
    """Iterate through all session entities, yielding each.

    Args:
      min_age_seconds: int seconds of minimum age sessions to return.
    """
    raise NotImplementedError

  def ExpireOne(self, session, now=None):
    """Expire old session data.

    Args:
      session: type unknown, one entire entity for one session record
      now: datetime.datetime, optional, current time
    Returns:
      True, if the session is too old to use and was deleted
      False, if the session is new enough to use
    """
    if self.IsExpired(session, now=now):
      self.Delete(session)
      return True
    else:
      return False

  def IsExpired(self, session, now=None):
    """Check whether session is expired."""
    if now is None:
      now = self._Now()
    age = datetime.timedelta(seconds=AGE_DEFAULT_SECONDS)

    session_mtime = self._Mtime(session)

    if session_mtime:
      d = now - session_mtime
    else:
      d = age + age  # undefined mtime, forcefully make it too old

    if d > age:
      return True
    else:
      return False

  @classmethod
  def DefineSessionType(cls, name, prefix):
    """Define a session type.

    This autogenerates 3 helper methods:

      SetName()
      GetName()
      DelName()

    And a constant SESSION_TYPE_PREFIX_NAME containing '{prefix}_'
    The Set/Get/Del methods use '{prefix}_' with all keys.

    Args:
      name: str, like 'token' (case will be adjusted)
      prefix: str, like 't' but not 't_'
    """
    sane_name = name[0].upper() + name[1:].lower()
    setattr(
        cls, 'SESSION_TYPE_PREFIX_%s' % name.upper(), '%s_' % prefix)
    setattr(
        cls, 'Set%s' % sane_name,
        lambda self, k, data=None, **kwargs: self.Set(
            '%s_%s' % (prefix, k), data, **kwargs))
    setattr(
        cls, 'Get%s' % sane_name,
        lambda self, k: self.Get('%s_%s' % (prefix, k)))
    setattr(
        cls, 'Del%s' % sane_name,
        lambda self, k: self.DeleteById('%s_%s' % (prefix, k)))


class AuthSessionData(object):
  """Class to hold session data as properties.

  This class is used to provide a consistent output interface
  between different AuthSession* objects.  This avoids returning
  dicts from some, objects with properties from others, etc.
  """

  def __init__(self, **kwargs):
    if kwargs:
      self.__dict__ = dict(kwargs)

  def __contains__(self, item):
    return item in self.__dict__

  def __eq__(self, other):
    if type(other) == dict:
      return self.__dict__ == other

    for k in self.__dict__:
      if not hasattr(other, k) or self.__dict__[k] != getattr(other, k):
        return False
    return True

  def __ne__(self, other):
    return not self.__eq__(other)


class AuthSessionDict(AuthSessionBase):
  """AuthSession storage using an in-memory dict.

  Uses a dict for indexing and AuthSessionData for session value data.
  """

  def __init__(self):
    self._sessions = {}

  def _Create(self, sid):
    """Create a session instance and return it.

    Args:
      sid: str, session id
    Returns:
      new session instance
    """
    return AuthSessionData(sid=sid, mtime=self._Now(), data=None)

  def _Get(self, sid):
    """Get a session instance from storage given its session id.

    Args:
      sid: str, session id
    Returns:
      session instance
    """
    return self._sessions.get(sid, None)

  def _Put(self, session):
    """Put a session instance into storage.

    Args:
      session: obj, session instance
    """
    self._sessions[session.sid] = session

  def DeleteById(self, sid):
    """Delete session data for a session id.

    Args:
      sid: str, session id
    """
    try:
      del self._sessions[sid]
    except KeyError:
      pass

  def Delete(self, session):
    """Delete one session.

    Args:
      session: obj, session instance
    """
    self.DeleteById(session.sid)

  def All(self, unused_min_age_seconds=None):
    """Iterate through all session entities, yielding each.

    Yields:
      session entity object
    """
    for session in self._sessions:
      yield self._sessions[session]


class Auth1ServerSession(AuthSessionDict):
  """AuthSession storage for Auth1 server."""

  AuthSessionBase.DefineSessionType('cn', 'cn')
  AuthSessionBase.DefineSessionType('token', 't')


class Auth1ClientSession(AuthSessionDict):
  """AuthSession storage for Auth1 client."""


class AuthBase(object):
  """Base authentication class."""

  def __init__(self):
    """Init."""
    self._output = None
    self._error_output = []
    self._session_class = self.GetSessionClass()
    self._session = self._session_class()
    self._default_state = self.DefaultState()
    self.ResetState()

  def GetSessionClass(self):
    return AuthSessionBase

  def DefaultState(self):
    """Return the default state of this auth class. Override in subclasses."""
    return State.NONE

  def ResetState(self):
    """Reset state and auth state to defaults."""
    self._state = self._default_state
    self._auth_state = AuthState.UNKNOWN

  def AuthFail(self):
    """Set state to failed auth."""
    self.ResetState()
    self._auth_state = AuthState.FAIL

  def _AddOutput(self, output):
    """Add output to the internal output buffer.

    Note: Also sets state to Output.

    Args:
      output: str, to concatenate to the output buffer
          or dict, to add to a dictionary output buffer
    """
    if self._output is not None:
      if type(output) is dict:
        self._output.update(output)
      else:
        self._output += output
    else:
      self._output = output
    self._state = State.OUTPUT

  def _AddError(self, errstr):
    """Add error output to the error output buffer.

    Args:
      errstr: str, to concatenate to the error output buffer
    """
    if self._error_output is None:
      self._error_output = [errstr]
    else:
      self._error_output.append(errstr)

  def ErrorOutput(self):
    """Return the errors output.

    Returns:
      list of strings, errors
    """
    err_output = self._error_output
    self._error_output = []
    return err_output

  def State(self):
    """Return the current state of the auth class.

    Returns:
      one of State.*
    """
    return self._state

  def Input(self, *unused_args, **unused_kwargs):
    """Accept input to auth methods."""
    if self._state == State.INPUT:
      # base class, we never do anything but accept input and
      # make no decisions.
      # subclasses, we return so that further action can occur.
      return
    raise ValueError('not waiting for input')

  def Output(self):
    """Output from auth methods.

    If the current state is not State.OUTPUT, nothing is returned.

    Returns:
      any data outputted from auth methods
    """
    if self._state == State.OUTPUT:
      output = self._output
      self._output = None
      # carefully return state to not waiting to output, but
      # don't change the auth_state.
      self._state = self._default_state
      return output

  def AuthState(self):
    """Return auth state.

    If state is OK or FAIL, only returns this value once before
    resetting to auth state UNKNOWN.  This is a paranoia feature.
    Consumers of this method will likely want to access this
    method once for the state, then if/branch off of the saved
    value.

    Returns:
      auth state, one of AuthState.*
    """
    auth_state = self._auth_state
    if self._auth_state in [AuthState.OK, AuthState.FAIL]:
      self.ResetState()
    return auth_state

  def AuthStateOK(self):
    """Returns True if auth state is OK, else False."""
    auth_state = self.AuthState()
    return auth_state == AuthState.OK

  def _SplitMessage(self, m, expect_len):
    """Load a message and return its items.

    Args:
      m: str, multiple items separated by MSG_SEP
      expect_len: int, number of items to expect and require in m
    Returns:
      list of items
    Raises:
      MessageError: if the message is malformed or has too few items
    """
    a = m.split(MSG_SEP)
    if len(a) != expect_len:
      raise MessageError('wrong number of message items %d %s', len(a), a)
    return a

  def _AssembleMessage(self, *args):
    """Export a message given items.

    Args:
      list of str items to include in the message
    Returns:
      string
    """
    return MSG_SEP.join(args)


class Auth1(AuthBase):
  """Auth class involving key exchange and signed messages.

  TODO(user): describe here or link to design doc
  """
  TOKEN = 'Auth1Token'

  def __init__(self, *args, **kwargs):
    super(Auth1, self).__init__(*args, **kwargs)
    self._key = None
    self._cert = None
    self._ca_pem = ''
    self._server_cert_pem = ''
    self._required_issuer = None

  def GetSessionClass(self):
    return Auth1ServerSession

  def DefaultState(self):
    """Default state is to wait for INPUT."""
    return State.INPUT

  def Nonce(self):
    """Return a nonce.

    Returns:
      int, 128-bit nonce
    """
    s = os.urandom(16)
    i = struct.unpack('QQ', s)  # QQ = two 8 byte unsigned ints
    i = (i[0] << 64) + i[1]
    return i

  def NonceBase64(self):
    """Return a nonce in base64 output.

    Returns:
      str, 128-bit nonce encoded in base64
    """
    return base64.urlsafe_b64encode(str(self.Nonce()))

  def GetCurrentEpochTimeUTC(self):
    """Return the current time, in epoch seconds, UTC.

    Returns:
      int, epoch seconds, UTC
    """
    return int(datetime.datetime.utcnow().strftime('%s'))

  def _AuthToken(self):
    """Return an auth token for this instance.

    Only returns a token if AuthState() is AuthState.OK.
    Can't be used in advance for this instance, etc.
    It is unlikely one would call this externally because of the
    auth state clearing nature of AuthState().

    Returns:
      str token (in form of a large random int, base64'd)
      None if auth_state is not OK
    """
    if self._auth_state == AuthState.OK:
      return self.NonceBase64()

  def _LoadCert(self, certstr):
    """Load a certificate and return a cert object.

    Args:
      certstr: str, cert in PEM format
    Returns:
      x509.X509Certificate instance
    Raises:
      ValueError: if the cert is malformed
    """
    try:
      cert = x509.LoadCertificateFromPEM(certstr)
    except x509.Error, e:
      raise ValueError(str(e))
    return cert

  def _LoadKey(self, keystr):
    """Load a key and return a key object.

    Args:
      keystr: str, key in PEM format
    Returns:
      tlslite.utils.RSAKey instance
    Raises:
      ValueError: keystr is improperly formed
    """
    try:
      key = tlslite_bridge.parsePEMKey(keystr)
    except (SyntaxError, AttributeError), e:
      raise ValueError('invalid PEM key format: %s' % str(e))
    return key

  def Sign(self, datastr):
    """Sign data with our loaded key.

    Args:
      datastr: str, to sign
    Returns:
      str output of signed data
    Raises:
      KeyNotLoaded: if no key has been loaded with LoadSelfKey()
    """
    if not self._key:
      raise KeyNotLoaded
    data_bytes = array.array('B')
    data_bytes.fromstring(datastr)
    sig_bytes = self._key.hashAndSign(data_bytes)

    if isinstance(sig_bytes, bytearray):
      # tlslite 0.4.9
      return str(sig_bytes)
    else:
      # tlslite 0.3.8 array.array
      return sig_bytes.tostring()

  def LoadSelfKey(self, keystr):
    """Load a key and keep it as this instance's key.

    Args:
      keystr: str, bytes of key in PEM format
    """
    key = self._LoadKey(keystr)
    self._key = key

  def LoadOtherCert(self, certstr):
    """Load a certificate and return a certificate object.

    Args:
      certstr: str, certificate in X509 PEM format
    Returns:
      x509.X509Certificate instance
    """
    return self._LoadCert(certstr)

  def LoadSelfCert(self, certstr):
    """Load a certificate and keep it as this instance's certificate.

    Args:
      certstr: str, certificate in X509 PEM format
    """
    cert = self._LoadCert(certstr)
    self._cert = cert
    self._cert_str = certstr

  def VerifyCertSignedByCA(self, cert):
    """Verify that a client cert was signed by the required CA cert.

    Args:
      cert: certificate object, client cert to verify
    Returns:
      True or False
    """
    ca_cert = self.LoadOtherCert(self._ca_pem)
    try:
      return cert.IsSignedBy(ca_cert)
    except (x509.Error, AssertionError), e:
      logging.exception(str(e))
      raise CryptoError(
          'VerifyCertSignedByCA: IsSignedBy: %s' % str(e))

  def VerifyDataSignedWithCert(self, data, signature, cert=None):
    """Verify that this cert signed this data.

    Args:
      data: str, data to verify signing
      signature: str, signature data
      cert: certificate object, or None for this instance's cert
    Returns:
      True or False
    Raises:
      CryptoError: if the underlying crypto APIs raise an assertion due to
        malformed data
    """
    if cert is None:
      cert = self._cert

    signature_b = array.array('B')
    signature_b.fromstring(str(signature))

    data_b = array.array('B')
    data_b.fromstring(str(data))

    try:
      pk = cert.GetPublicKey()
      return pk.hashAndVerify(signature_b, data_b)
    except AssertionError, e:
      logging.exception(str(e))
      raise CryptoError(
          'VerifyDataSignedWithCert: hashAndVerify: %s' % str(e))

  def SessionSetCnSn(self, cn, sn):
    """Set a known Cn, Sn pair in sessions.

    Args:
      cn: str, client nonce
      sn: str, server nonce
    """
    self._session.SetCn(str(cn), str(sn))

  def SessionVerifyKnownCnSn(self, cn, sn):
    """Verify that a Cn, Sn pair is known.

    Args:
      cn: str, client nonce
      sn: str, server nonce
    Returns:
      bool, True if the pair is known (exists in session db)
    """
    orig_sn = self._session.GetCn(str(cn))
    # Get() returns None if the session is not found.
    # carefully check for None here so that a cn lookup with None
    # for sn value does not create a false positive.
    if orig_sn is None:
      h = 'SessionVerifyKnownCnSn(%s,%s)' % (str(cn), str(sn))
      logging.debug('%s: orig_sn is None', h)
      return False
    elif orig_sn == AuthState.OK:
      h = 'SessionVerifyKnownCnSn(%s,%s)' % (str(cn), str(sn))
      logging.debug('%s: orig_sn != AuthState.OK', h)
      return False
    elif orig_sn != sn:
      h = 'SessionVerifyKnownCnSn(%s,%s)' % (str(cn), str(sn))
      logging.debug('%s: orig_sn (%s) != sn (%s)', h, orig_sn, sn)
      return False

    return True

  def GetSessionIfAuthOK(self, token, require_level=None):
    """Check if auth is OK for a given token.

    Args:
      token: str, token string from SessionCreateAuthToken
      require_level: int, optional, require this token to have at least
          level require_level access
    Returns:
      session object if the auth token is known, state OK, level OK.
    Raises:
      AuthSessionError: auth token is unknown, state is not OK, or level not OK.
    """
    session = self._session.GetToken(token)

    if not session:
      raise AuthSessionError('GetSessionIfAuthOK: session is None')
    elif session.state != AuthState.OK:
      raise AuthSessionError(
          'GetSessionIfAuthOK: state (%s) != OK', session.state)

    if require_level is not None and require_level > session.level:
      raise AuthSessionError(
          'GetSessionIfAuthOK: require_level (%s) session level (%s)',
          require_level, session.level)

    return session

  def SessionGetUuid(self, token):
    """Retrieve uuid for a given token.

    Args:
      token: str, token string from SessionCreateAuthToken
    Returns:
      uuid str OR
      None if token does not exist
    """
    session = self._session.GetToken(token)
    return getattr(session, 'uuid', None)

  def SessionCreateAuthToken(self, uuid, level=LEVEL_BASE):
    """Create an auth token and set it in the session db.

    Args:
      uuid: str, uuid for client which is receiving token
      level: int, optional, default LEVEL_BASE, level for session
    Returns:
      str, token
    """
    token = self._AuthToken()
    self._session.SetToken(token, state=AuthState.OK, uuid=uuid, level=level)
    return token

  def SessionCreateUserAuthToken(self, user, level=LEVEL_BASE):
    """Create a session for a user who has already been authenticated.

    Only call this method when some other type of authentication has
    already occured, for example a SSO system, has validated this user.
    The token returned is fully authenticated and receiver will be able
    to immediately use it.

    Args:
      user: str, some user id like 'foo' or 'foo@example.com', etc
      level: int, optional, default LEVEL_BASE, level for session
    Returns:
      str, token
    """
    self.ResetState()
    user = str(user)
    self._auth_state = AuthState.OK
    token = self.SessionCreateAuthToken(uuid=user, level=level)
    self.ResetState()
    return token

  def SessionDelCn(self, cn):
    """Delete any session data for a Cn.

    Args:
      cn: str, client nonce
    """
    self._session.DelCn(str(cn))

  def SessionDelToken(self, token):
    """Delete a token from session data.

    Args:
      token: str, token string from SessionCreateAuthToken
    """
    self._session.DelToken(token)

  def Input(self, n=None, m=None, s=None):  # pylint: disable=arguments-differ
    """Input parameters to the auth function.

    Callers should provide n, OR m and s.

    Args:
      n: str, nonce from client, an integer in str form e.g. '12345'
      m: str, message from client
      s: str, b64 signature from client
    Raises:
      ValueError: if invalid combination of arguments supplied
    """
    super(Auth1, self).Input()
    self.ResetState()  # paranoia clear auth_state, tests run OK without

    if n is not None and m is None and s is None:
      #logging.debug('Auth step 1')

      try:
        cn = int(n)
      except ValueError:
        logging.critical('Non-integer Cn was supplied: %s', str(n))
        self.AuthFail()
        return

      if cn < MIN_VALUE_CN:
        logging.critical('Cn value is too small: %d', cn)
        self.AuthFail()
        return

      sn = self.Nonce()
      m = self._AssembleMessage(str(cn), str(sn))
      sig = self.Sign(m)
      sig = base64.urlsafe_b64encode(sig)
      m = self._AssembleMessage(m, sig)
      self._AddOutput(m)
      self.SessionSetCnSn(cn, sn)
      #logging.debug('Server supplied Sn %s for Cn %s', sn, cn)
    elif m is not None and s is not None and n is None:
      #logging.debug('Auth step 2')

      class _Error(Exception):
        """Temporary exception used here."""

      log_prefix = ''
      cn = None

      try:
        # open up the message to get the client cert 'c'.
        try:
          (c, cn, sn) = self._SplitMessage(m, 3)
        except MessageError, e:
          raise _Error('SplitMessage MessageError (%s)', str(e))

        log_prefix = ''

        # signature 's' and client cert 'c' are urlsafe_base64
        try:
          s = base64.urlsafe_b64decode(str(s))
          c = base64.urlsafe_b64decode(str(c))
        except TypeError, e:
          raise _Error('Invalid c or s parameter b64 format(%s)', str(e))

        # load X509 client cert 'c' into object
        try:
          client_cert = self.LoadOtherCert(c)
        except ValueError, e:
          raise _Error('Invalid cert supplied %s' % str(e))

        # sanity check
        if not client_cert.GetPublicKey():
          raise _Error('Malformed X509 cert with no public key')

        client_cert.SetRequiredIssuer(self._required_issuer)
        try:
          client_cert.CheckAll()
        except x509.Error, e:
          raise _Error('X509 certificate error: %s' % str(e))

        # obtain uuid from cert
        uuid = client_cert.GetSubject()
        log_prefix = uuid

        # client_cert is loaded
        #logging.debug('%s Client cert loaded', log_prefix)
        #logging.debug('%s Message = %s', log_prefix, m)

        # verify that the client cert is legitimate
        if not self.VerifyCertSignedByCA(client_cert):
          raise _Error('Client cert is not signed by the required CA')

        # verify that the message was signed by the client cert
        if not self.VerifyDataSignedWithCert(m, s, client_cert):
          raise _Error('Signed message does not verify')

        # verify that the Sn was the one offered to this Cn previously
        if not self.SessionVerifyKnownCnSn(cn, sn):
          raise _Error('Client offered unknown Sn %s', sn)

        # success!
        #logging.debug('%s Client auth successful', log_prefix)

        # careful here, switching the state setting and AddOutput
        # lines causes a hard to test bug (because Input() test mocks out
        # AuthToken())
        self._auth_state = AuthState.OK
        token = self.SessionCreateAuthToken(uuid)
        self._AddOutput(token)

      except (_Error, CryptoError), e:
        logging.warning('%s Auth error: %s', log_prefix, e.args)
        logging.debug('%s Auth message: %s', log_prefix, m)
        logging.debug(
            '%s Auth sig: %s', log_prefix, base64.urlsafe_b64encode(s))
        self.AuthFail()

      # no matter what, delete the current cn:sn pair if an attempt
      # was made to auth against it, success or not.
      if cn is not None:
        self.SessionDelCn(cn)
    else:
      #logging.debug('Auth step unknown')
      raise ValueError('invalid input')


class Auth1Client(Auth1):
  """Client class for Auth1 style auth."""

  def __init__(self, *args, **kwargs):
    super(Auth1Client, self).__init__(*args, **kwargs)
    self._key = None   # this client's private key

  def GetSessionClass(self):
    return Auth1ClientSession

  def Input(self, m=None, t=None):  # pylint: disable=arguments-differ
    """Accept input to auth methods.

    Callers should provide either m OR t, or neither, but not both.

    Args:
      m: str, message from server (cn, sn, signature)
      t: str, token reply from server
    Raises:
      ValueError: if invalid combination of arguments supplied
    """
    self.ResetState()

    # no input - step 0, producing step 1 input
    if m is None and t is None:
      cn = str(self.Nonce())
      self._AddOutput(cn)
      self._session.Set('cn', cn)

    # message input - step 1 output, produce step 2 input
    elif m is not None and t is None:

      class _Error(Exception):
        """Temporary exception used here."""

      cn = None

      try:
        # open up the message to get the client nonce (cn),
        # server nonce (sn) and signature (s)
        try:
          (cn, sn, s) = self._SplitMessage(m, 3)
        except MessageError, e:
          raise _Error('SplitMessage MessageError (%s)' % str(e))

        try:
          s = base64.urlsafe_b64decode(str(s))
        except TypeError, e:
          raise _Error('Invalid s parameter b64 format (%s)' % str(e))

        # verify cert is a server cert
        try:
          server_cert = self.LoadOtherCert(self._server_cert_pem)
        except ValueError, e:
          raise _Error('Server cert load error: %s' % str(e))
        if not self.VerifyCertSignedByCA(server_cert):
          raise _Error('Server cert is not signed by known CA')

        # load the Cn value that this client used previously
        orig_cn = self._session.Get('cn')
        if cn != orig_cn:
          raise _Error('Server supplied Cn does not match our Cn')

        # verify signature on message "Cn Sn"
        tmp_m = self._AssembleMessage(cn, sn)
        if not self.VerifyDataSignedWithCert(tmp_m, s, server_cert):
          raise _Error('Sn is not signed by server cert')

        # create return message: base64_client_cert cn sn
        c = base64.urlsafe_b64encode(self._cert_str)
        out_m = self._AssembleMessage(c, cn, sn)

        sig = self.Sign(out_m)
        sig = base64.urlsafe_b64encode(str(sig))

        #logging.debug('M= %s', out_m)
        #logging.debug('S= %s', sig)

        self._AddOutput({'m': out_m, 's': sig})
      except _Error, e:
        self._session.DeleteById('cn')
        self._AddError(str(e))
        self.AuthFail()

    # token input - step 3 input
    elif t is not None and m is None:
      if t == Auth1.TOKEN:
        self._session.DeleteById('cn')
        self.ResetState()
        self._auth_state = AuthState.OK
      else:
        self.AuthFail()

    # unknown input
    else:
      raise ValueError('Invalid input')
