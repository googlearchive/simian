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

"""Module containing classes to connect to Simian as a client."""




import base64
import cPickle as Pickle
import datetime
import errno
import getpass
import httplib
import logging
import mimetools
import os
import os.path
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib
import urlparse
import warnings
warnings.filterwarnings(
    'ignore', '.* md5 module .*', DeprecationWarning, '.*', 0)
from M2Crypto import SSL
try:
  import google.appengine.tools.appengine_rpc
except ImportError:
  from pkgutil import extend_path as _extend_path
  import google
  _path = '%s/gae_client.zip' % os.path.dirname(os.path.realpath(__file__))
  google.__path__ = _extend_path(['%s/google/' % _path], google.__name__)
  sys.path.insert(0, _path)
from simian import settings
from simian.auth import client as auth_client
from simian.auth import x509
from simian.auth import settings as auth_settings
from google.appengine.tools import appengine_rpc

# seek constants moved from posixfile(2.4) to os(2.5+)
if sys.version_info[0] <= 2 and sys.version_info[1] <= 4:
  import warnings
  warnings.filterwarnings(
      'ignore', '', DeprecationWarning, 'posixfile', 0)
  import posixfile as _stdio
else:
  import os as _stdio


SERVER_HOSTNAME_REGEX = settings.SERVER_HOSTNAME_REGEX
SERVER_HOSTNAME = settings.SERVER_HOSTNAME
SERVER_PORT = settings.SERVER_PORT
FACTER_CMD = ['/usr/local/bin/simianfacter']
CLIENT_SSL_PATH = auth_settings.CLIENT_SSL_PATH
SEEK_SET = _stdio.SEEK_SET
SEEK_CUR = _stdio.SEEK_CUR
SEEK_END = _stdio.SEEK_END
DEBUG = False
if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)
URL_UPLOADPKG = '/uploadpkg'


class Error(Exception):
  """Base class."""


class HTTPError(Error):
  """HTTP error."""


class SimianServerError(Error):
  """Simian server error."""


class SimianClientError(Error):
  """Simian client error."""


class SudoExecError(Error):
  """Error in SudoExec."""


class PuppetSslCertError(Error):
  """Error in _GetPuppetSslDetailsForCert."""


class FacterError(Error):
  """Error when using facter."""


class Response(object):
  """Response from https server."""

  status = None
  reason = None
  headers = None
  body = None
  body_len = None

  def __init__(
      self, status, reason=None, body=None, headers=None, body_len=None):
    """Init the instance.

    Args:
      status: int, like 200, 400, etc
      reason: str, like 'Bad Request' or 'OK'
      headers: dict or list, like
          {'Content-type': 'foo'} or
          [('Content-type', 'foo')]
      body: str, optional, body of the response
      body_len: int, optional, length of the response body
    """
    self.status = status
    self.reason = reason
    self.body = body
    self.body_len = body_len

    if type(headers) is dict:
      self.headers = headers
    elif type(headers) is list:
      headers_dict = {}
      for k, v in headers:
        headers_dict[k] = v
      self.headers = headers_dict

  def IsSuccess(self):
    """Returns True on success, False otherwise."""
    return self.status >= 200 and self.status <= 299

  def IsRedirect(self):
    """Returns True on redirect, False otherwise."""
    return self.status >= 300 and self.status <= 399

  def IsClientError(self):
    """Returns True on client error, False otherwise."""
    return self.status >= 400 and self.status <= 499

  def IsServerError(self):
    """Returns True on server error, False otherwise."""
    return self.status >= 500 and self.status <= 599

  def IsError(self):
    """Returns True on client or server error, False otherwise."""
    return self.status >= 400 and self.status <= 599


class MultiBodyConnection:
  """Connection which can send multiple items as request body."""

  # types we are willing to send in one block
  DIRECT_SEND_TYPES = [str]

  def SetProgressCallback(self, fn):
    """Set function to callback to with transfer progress.

    Args:
      fn: function which will receive (bytes sent, bytes total to send)
          arguments
    Raises:
      Error: if non callable item is passed as fn
    """
    if not callable(fn):
      raise Error('SetProgressCallback argument fn must be callable')
    self._progress_callback = fn

  def _ProgressCallback(self, bytes_sent, bytes_total):
    """Call the progress callback with current transfer data.

    Args:
      bytes_sent: int, bytes sent
      bytes_total: int, total bytes that will be sent
    """
    if hasattr(self, '_progress_callback'):
      self._progress_callback(bytes_sent, bytes_total)

  def request(self, method, url, body=None, headers=None):
    """Send HTTP/HTTPS request.

    The arguments are the same as httplib.HTTPConnection.request(),
    except for the argument "body".

    Args:
      method: str, like 'GET'
      url: str, url like '/path', not like 'http://server/path'
      body: list or str or file-like obj.

        If a list, multiple items are sent in list order.

        For each item, if a str is passed, it is sent directly.  If a file
        or file-like object (implementing tell(), seek(), read()) is
        supplied, it is read from in blocks and output directly into
        the HTTP stream.  This facilitates sending large files, etc without

      headers: dict, headers to supply
    """
    if headers is None:
      headers = {}

    if body is not None:
      if type(body) is list:
        multibody = body
      else:
        multibody = [body]

      content_length = 0
      for body in multibody:
        if type(body) in self.DIRECT_SEND_TYPES:
          content_length += len(body)
        elif hasattr(body, 'tell') and hasattr(
            body, 'seek') and hasattr(body, 'read'):
          orig_pos = body.tell()
          body.seek(0, SEEK_END)
          content_length += body.tell() - orig_pos
          body.seek(orig_pos, SEEK_SET)
        else:
          raise NotImplementedError('multibody for type %s' % type(body))

      # supply this pre-calculated value to stop the parent class
      # from trying to figure it out with len().
      headers['Content-Length'] = content_length
    else:
      multibody = []
      content_length = 0

    # IMPORTANT WORKAROUND for AppEngine /_ah/upload/ service.
    #
    # Python's HTTPConnection adds a ':port' suffix to the Host header
    # when the port is not 80.  In this case we might be using
    # https so the Host header becomes "host:443".
    #
    # AppEngine 500s when it receives a Host header like
    # "APPID.appspot.com:443".
    #
    # So, we self-assign the Host header and HTTPConnection won't
    # auto-calculate it for us.
    #

    # TODO(user): This is the most conservative fix. We know that
    # AppEngine will tolerate Host: foo(noportspecified) for a https
    # tcp/443 connection.  Upon further investigation with AppEngine
    # Upload Service we could possibly refine this logic further.
    if self._is_https and self.port == 443:
      headers['Host'] = self.host

    # don't pass a body here -- let's manage sending it ourselves.
    # the connection is ready for it after this request() completes.
    httplib.HTTPConnection.request(
        self, method, url, body=None, headers=headers)

    bytes_sent = 0
    self._ProgressCallback(bytes_sent, content_length)

    # now, send the body sections, the connection is ready.
    for body in multibody:
      if type(body) in self.DIRECT_SEND_TYPES:
        if body != '':  # sending '' blows up M2Crypto write() sometimes.
          self.send(body)
          bytes_sent += len(body)
          self._ProgressCallback(bytes_sent, content_length)
      else:
        buf = body.read(8192)
        while buf != '':
          self.send(buf)
          bytes_sent += len(buf)
          self._ProgressCallback(bytes_sent, content_length)
          buf = body.read(8192)

    self._ProgressCallback(bytes_sent, content_length)


class HTTPMultiBodyConnection(MultiBodyConnection, httplib.HTTPConnection):
  """HTTP multi-body connection implemented over HTTP."""
  _is_https = False


class HTTPSMultiBodyConnection(MultiBodyConnection, httplib.HTTPSConnection):
  """HTTP multi-body connection implemented over HTTPS."""

  _is_https = True

  def __init__(self, *args, **kwargs):
    #Note: MultiBodyConnection has no __init__. Change this if it ever does.
    #MultiBodyConnection.__init__(*args, **kwargs)
    httplib.HTTPSConnection.__init__(self, *args, **kwargs)
    self._cert_valid_subject_matches = []
    self._cert_valid_subjects = []
    self._cert_require_subjects = []

  @classmethod
  def SetCACertChain(self, certs):
    """Set the CA certificate chain to verify SSL peer (server) certs.

    NOTE:  Without having called this method to set a CA chain to verify
    against, calling connect() in the future will fail out of paranoia.

    Args:
      certs: str, one or more X509 certificates concatenated after
        another.  the only required delimiter between certs is that
        each cert start on a new line.  (but an empty line is not required)
    """
    self._ca_cert_chain = certs

  def SetCertValidSubjects(self, valid_subjects):
    """Set a list of certificate subjects which are the only valid ones.

    For example, to lock down a client to only accept one known signing
    authority and the final subject for the destination https server:

        SetCertValidSubjects(['O=SigningAuthority'],['CN=www.example.com'])

    If this method is not called, normal cert validity rules apply
    by validating the x509 cert chain inside M2Crypto.

    Args:
      valid_subjects: list of str, valid subjects
    Raises:
      ValueError: if strict value supplied is not a list of str
    """
    if type(valid_subjects) is not list:
      raise ValueError('valid_subjects must be a list')
    for x in valid_subjects:
      if type(x) is not str:
        raise ValueError('all members of valid_subjects must be str')
    logging.debug('SetCertValidSubjects(%s)', valid_subjects)
    self._cert_valid_subjects = valid_subjects

  def SetCertRequireSubjects(self, require_subjects):
    """Set a list of certificate subjects which are required to appear.

    For example, to require a client see a specific subject:

        SetCertRequireSubjects(['CN=www.example.com'])

    If this method is not called, normal cert validity rules apply
    by validating the x509 cert chain inside M2Crypto.

    Each of the subjects in require_subjects must have already been defined
    as a valid subject by using SetCertValidSubjects().  If a subject
    supplied in require_subjects is not in valid subjects, an exception will
    be raised.  (This is a defense since the subject would not have been put
    into _cert_valid_subject_matches without being in _cert_valid_subjects
    to begin with.)

    Args:
      require_subjects: list of str, require subjects
    Raises:
      ValueError: if strict value supplied is not a list of str
    """
    if type(require_subjects) is not list:
      raise ValueError('require_subjects must be a list')
    for x in require_subjects:
      if type(x) is not str:
        raise ValueError('all members of require_subjects must be str')
      if x not in self._cert_valid_subjects:
        raise ValueError('subject %s not in valid subjects' % x)
    logging.debug('SetCertRequireSubjects(%s)', require_subjects)
    self._cert_require_subjects = require_subjects

  def _IsValidCert(self, ok, store):
    """Determine whether a cert is valid.

    This method is called from M2Crypto set_verify as a hook.  It is called
    once for each cert in the chain that is used to validate the SSL
    connection.

    Args:
      ok: int, always 1 or 0
      store: M2Crypto.X509.X509_Store_Context
    Returns:
      1 if valid, 0 if not
    """
    # no valid subjects list, so don't perform any additional checks.
    if self._cert_valid_subjects == []:
      return 1

    subject = str(store.get_current_cert().get_subject())

    # if openssl has verified this cert ok==1, otherwise 0.
    if ok != 1:
      logging.debug(
          'IsValidCert() ok=%s cert=%s, returning 0', str(ok), subject)

    valid = (ok == 1) and subject in self._cert_valid_subjects

    if valid:
      self._cert_valid_subject_matches.append(subject)

    logging.debug(
        '_IsValidCert(): subject=%s, VALID=%s', subject, valid)

    return valid * 1

  def _LoadCACertChain(self, ctx):
    """Load a CA certificate chain into a SSL context and set the
    context verify modes to require certificate validation on the peer's
    cert.

    Args:
      ctx: M2Crypto.SSL.Context, to load certificate chain into
    Returns:
      None if successful
    Raises:
      SimianClientError: if any errors occur in finding a chain of
        certs to load (e.g. none supplied), or in parsing and loading them
    """
    if not hasattr(self, '_ca_cert_chain'):
      raise SimianClientError('Missing CA certificate chain')

    tf = tempfile.NamedTemporaryFile()
    tf.write(self._ca_cert_chain)
    tf.flush()

    if ctx.load_verify_locations(cafile=tf.name) != 1:
      tf.close()
      raise SimianClientError('Could not load CA certificate chain')

    self._cert_valid_subject_matches = []

    ctx.set_verify(
        SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
        depth=9,
        callback=self._IsValidCert)

    tf.close()
    logging.debug(
        'Loaded %d bytes of CA cert chain and configured ctx',
        len(self._ca_cert_chain))

  def connect(self):
    """Connect to the host and port specified in __init__."""
    server_address = ((self.host, self.port))
    ctx = SSL.Context()

    if hasattr(self, '_ca_cert_chain'):
      self._LoadCACertChain(ctx)
    else:
      raise SimianClientError('Missing CA certificate chain')

    logging.debug('SSL configuring with context')
    sock = SSL.Connection(ctx)
    logging.debug('SSL connect(%s)', server_address)
    sock.connect(server_address)

    # If this client is validating cert subjects, make sure that some
    # certs were validated.  This is done to prove our callback
    # was invoked.
    #
    # Additionally, make sure that any cert subjects which were
    # required to appear did so.
    if self._cert_valid_subjects:

      if not self._cert_valid_subject_matches:
        raise SimianClientError('No certificate subjects were validated')

      for subject in self._cert_require_subjects:
        if subject not in self._cert_valid_subject_matches:
          raise SimianClientError(
              'Certificate subject %s was not validated' % subject)

    logging.debug('SSL connected %s', server_address)
    self.sock = sock
    # Note we are dropping HTTP CONNECT tunnel support by not handling
    # _tunnel_* options here, see original HTTPConnection.connect().


class HTTPSHandler(appengine_rpc.urllib2.HTTPSHandler):
  """Handler object to advertise https support to urllib2."""

  def https_open(self, req):
    # this function is the same as urllib2.HTTPSHandler, except we
    # return our HTTPS class, not the default httplib.HTTPSConnection.
    return self.do_open(HTTPSMultiBodyConnection, req)


class AppEngineHttpRpcServer(appengine_rpc.HttpRpcServer):
  """HttpRpcServer subclass which uses safe SSL."""

  def _GetOpener(self):
    """Returns an OpenerDirector that supports cookies and ignores redirects.

    This method calls the original _GetOpener in appengine_rpc.  In this
    local modification we temporarily stub out
    urllib2.OpenerDirector.add_handler to stop appengine_rpc from loading
    FancyHTTPSHandler, and inject our HTTPSHandler instead.

    Returns:
      A urllib2.OpenerDirector object.
    """
    _orig_add_handler = appengine_rpc.urllib2.OpenerDirector.add_handler

    def _add_handler(self, handler):
      if not isinstance(handler, appengine_rpc.fancy_urllib.FancyHTTPSHandler):
        _orig_add_handler(self, handler)
      else:
        _orig_add_handler(self, HTTPSHandler())

    appengine_rpc.urllib2.OpenerDirector.add_handler = _add_handler
    opener = super(AppEngineHttpRpcServer, self)._GetOpener()
    appengine_rpc.urllib2.OpenerDirector.add_handler = _orig_add_handler
    return opener


class HttpsClient(object):
  """Connect to a http or https service.

  Defaults to https unless if overridden with a URL-style hostname,
  e.g. "http://...."
  """

  def __init__(self, hostname, port=None):
    """Init."""
    self._LoadHost(hostname, port)
    self._progress_callback = None
    self._ca_cert_chain = None
    self._cert_valid_subjects = None
    self._cert_require_subjects = None

  def SetProgressCallback(self, fn):
    self._progress_callback = fn

  def SetCACertChain(self, certs):
    """Set the CA certificate chain to verify SSL server certs.

    Args:
      certs: str, one or more X509 certificates concatenated after
        another
    """
    self._ca_cert_chain = certs

  def _EnableRFC2818Workaround(self):
    """Enable non-RFC2818 behavior to be less strict about DNS cert checks.

    Per RFC2818 a * in the cert DNS name only wildcards one DNS subdomain
    level, but this breaks matching versioned AppEngine domains, e.g.
        X.latest.APPID.example.com should match *.example.com
    """
    if hasattr(SSL.Checker.Checker, '_orig_match'):
      return

    logging.debug('EnableRFC2818Workaround(): overriding Checker._match')

    def _replacement_match(x, host, cert_host):
      """Replacement DNS match function to be less RFC compliant.

      Args:
        x: instance of SSL.Checker.Checker
        host: str, hostname to look at, e.g. "X.latest.APPID.example.com"
        cert_host: str, domain to match against, e.g.
            "exact.example.com" or "*.example.com"
      Returns:
        True or False
      """
      if SSL.Checker.Checker._orig_match(x, host, cert_host):
        return True

      cert_host = cert_host.replace('.', '\\.')
      cert_host = cert_host.replace('*', '.*')

      if re.search('^%s$' % cert_host, host, re.IGNORECASE):
        logging.debug(
            ('EnableRFC2818Workaround(): Matched positive %s against %s when '
             'default would not have'),
            host, cert_host)
        return True
      return False

    SSL.Checker.Checker._orig_match = SSL.Checker.Checker._match
    SSL.Checker.Checker._match = _replacement_match
    logging.debug('EnableRFC2818Workaround(): enabled')

  def _DisableRFC2818Workaround(self):
    """Disable non-RFC2818 behavior to be less strict about DNS cert checks.

    See _EnableRFC2818Workaround() for full explanation.
    """
    if not hasattr(SSL.Checker.Checker, '_orig_match'):
      return

    SSL.Checker.Checker._match = SSL.Checker.Checker._orig_match
    del(SSL.Checker.Checker._orig_match)
    logging.debug('DisableRFC2818Workaround(): disabled')

  def _LoadHost(self, hostname, port=None):
    """Load hostname and port to connect to.

    Args:
      hostname: str, like a URL or a hostname string.  Examples:
        'http://foo' 'http://foo:port' 'https://foo' 'foo:port' 'foo'
      port: int, optional, port to connect to, which will be overriden by
        any port specified in the hostname str.
    Raises:
      Error: if hostname is malformed
    """
    logging.debug('LoadHost(%s, %s)', hostname, port)

    if not hostname.startswith('http'):
      hostname = 'https://%s' % hostname

    (scheme, netloc, path, query, frag) = urlparse.urlsplit(hostname)

    (hostname, tmp_port) = urllib.splitport(netloc)
    if tmp_port:
      port = tmp_port

    use_https = False
    if scheme == 'https':
      use_https = True

    if port:
      try:
        port = int(port)
      except TypeError:
        raise Error('invalid port value %s' % str(port))

    if port == 80 and not use_https:
      port = None
    if port == 443 and use_https:
      port = None

    self.hostname = hostname
    self.port = port
    self.netloc = self.hostname
    self.use_https = use_https

    if self.port and self.port != 80 and self.port != 443:
      self.netloc = '%s:%d' % (self.netloc, self.port)

    logging.debug('LoadHost(): hostname = %s, port = %s, use_https = %s',
        self.hostname, self.port, self.use_https)

    if SERVER_HOSTNAME_REGEX.search(hostname):
      self._EnableRFC2818Workaround()
    else:
      self._DisableRFC2818Workaround()

  def _AdjustHeaders(self, headers):
    """Adjust headers before a request.

    Override in subclasses.

    Args:
      headers: dict, headers that will be passed to a http request
    """

  def _Connect(self, hostname, port=None):
    """Return a HTTPSConnection object connected to host:port.

    Args:
      hostname: str, hostname
      port: int, optional, port number
    Returns:
      HTTPConnection object
    """
    if self.use_https:
      conn = HTTPSMultiBodyConnection(hostname, port=port)
    else:
      conn = HTTPMultiBodyConnection(hostname, port=port)

    if self._progress_callback is not None:
      conn.SetProgressCallback(self._progress_callback)

    if self.use_https:
      if self._ca_cert_chain is not None:
        conn.SetCACertChain(self._ca_cert_chain)
      if self._cert_valid_subjects is not None:
        conn.SetCertValidSubjects(self._cert_valid_subjects)
      if self._cert_require_subjects is not None:
        conn.SetCertRequireSubjects(self._cert_require_subjects)

    try:
      conn.connect()
    except httplib.socket.error, e:
      raise SimianClientError(str(e))
    return conn

  def _GetResponse(self, conn, output_file=None):
    """Obtain a response from the connection and interpret it.

    Args:
      conn: HTTP{,S}Connection
      output_file: file, optional, file to write response body to
    Returns:
      Response instance
    """
    response = conn.getresponse()
    headers = response.getheaders()
    status = response.status
    reason = response.reason
    body_len = 0

    read_len = 8192   # some arbitrary block size

    if output_file:
      buf = response.read(read_len)
      while buf:
        body_len += len(buf)
        output_file.write(buf)
        buf = response.read(read_len)
      body = None
    else:
      body = response.read()
      body_len = len(body)

    return Response(
        status=status, reason=reason,
        headers=headers, body=body, body_len=body_len)

  def _Request(self, method, conn, url, body=None, headers=None):
    """Make a https request on the supplied connection.

    Args:
      method: str, like 'GET' or 'POST'
      conn: HTTP{,S}Connection
      url: str, url to connect to, starting with the first /
      body: str or dict or file, optional, body to send with request
      headers: dict, dictionary of headers to supply
    """
    if body is not None and type(body) is dict:
      body = urllib.urlencode(body)
    self._AdjustHeaders(headers)
    # smash url to str(), in case unicode has slipped in, which never
    # sends properly.
    conn.request(method, str(url), body=body, headers=headers)

  def _DoRequestResponse(
      self, method, hostname, url,
      body=None, headers=None, port=None, output_file=None):
    """Connect to hostname, make a request, obtain response.

    Args:
      method: str, like 'GET' or 'POST'
      hostname: str, hostname like 'foo.com', not 'http://foo.com'
      url: str, url like '/foo.html', not 'http://host/foo.html'
      body: str or dict or file, optional, body to send with request
      headers: dict, optional, headers to send with request
      port: int, optional, port to connect on
      output_file: file, optional, file to write response body to
    Returns:
      Response instance
    Raises:
      HTTPError: if a connection level error occured
    """
    try:
      suffix = self.use_https * 's'
      logging.debug('Connecting to http%s://%s:%s', suffix, hostname, port)
      conn = self._Connect(hostname, port)
      logging.debug('Requesting %s %s', method, url)
      self._Request(method, conn, url, body=body, headers=headers)
      logging.debug('Waiting for response')
      response = self._GetResponse(conn, output_file=output_file)
      logging.debug('Response status %d', response.status)
      return response
    except httplib.HTTPException, e:
      raise HTTPError(str(e))

  def Do(
      self, method, url,
      body=None, headers=None, output_filename=None, _open=open):
    """Make a request and return the response.

    Args:
      method: str, like 'GET' or 'POST'
      url: str, url like '/foo.html', not 'http://host/foo.html'
      body: str or dict or file, optional, body to send with request
      headers: dict, optional, headers to send with request
      output_filename: str, optional, filename to write response body to
      _open: func, optional, default builtin open, to open output_filename
    Returns:
      Response object
    Raises:
      NotImplementedError: if an unknown method is supplied
      HTTPError: if a connection level error occured
    """
    if method not in ['GET', 'POST', 'PUT', 'DELETE']:
      raise NotImplementedError('HTTP method %s' % method)

    if headers is None:
      headers = {}

    if output_filename:
      output_file = _open(output_filename, 'w')
    else:
      output_file = None

    response = self._DoRequestResponse(
        method, self.hostname, url,
        port=self.port, body=body, headers=headers, output_file=output_file)

    if output_filename:
      output_file.close()

    return response

  def DoMultipart(
      self, url, params, filename, input_filename=None, input_file=None):
    """Make a form/multipart POST request and return the response.

    Args:
      url: str, url like '/foo.html', not 'http://host/foo.html'
      params: dict, text parameters to send as text/plain form elements
      filename: str, filename to be supplied in headers, it is NOT read from
      input_filename: str, optional, filename to read from
      input_file: file, optional, file object to read from
    Returns:
      Response object
    Raises:
      HTTPError: if a connection level error occured
    """
    if not input_filename and not input_file:
      raise Error('must supply input_filename or input_file')

    boundary = mimetools.choose_boundary()
    content_type = 'application/octet-stream'
    headers = {
        'Content-Type': 'multipart/form-data; boundary=%s' % boundary,
    }

    output = []

    close_input_file = False
    if input_file is None:
      close_input_file = True
      input_file = open(input_filename, 'r')

    CRLF = '\r\n'
    body = []

    # TODO(user): This method should support sending multiple files,
    # not just one.
    tmp_body = []
    tmp_body.append('--%s' % boundary)
    tmp_body.append(
        ('Content-Disposition: form-data; name="file"; '
         'filename="%s"' % filename))
    tmp_body.append('Content-Type: %s' % content_type)
    tmp_body.append('')

    body.append(CRLF.join(tmp_body))
    body.append(CRLF)
    body.append(input_file)
    body.append(CRLF)

    tmp_body = []
    for k, v in params.iteritems():
      tmp_body.append('--%s' % boundary)
      tmp_body.append(
          'Content-Disposition: form-data; name="%s"' % k)
      tmp_body.append('Content-type: text/plain; charset=utf-8')
      tmp_body.append('')
      tmp_body.append(v)

    body.append(CRLF.join(tmp_body))
    body.append('%s--%s--%s' % (CRLF, boundary, CRLF))
    body.append(CRLF)

    try:
      response = self.Do('POST', url, body=body, headers=headers)
    except:
      if close_input_file:
        input_file.close()
      raise

    if close_input_file:
      input_file.close()

    return response


class UAuth(object):
  """Class to authenticate to /uauth with user credentials."""

  def __init__(self, hostname=None, interactive_user=True):
    """init.

    Args:
      hostname: str, optional, default SERVER_HOSTNAME:SERVER_PORT,
          hostname to connect to.
      interactive_user: bool, optional, default True, whether interactive
          user is present.
    """
    if hostname is None:
      hostname = '%s:%s' % (SERVER_HOSTNAME, SERVER_PORT)
    self.hostname = hostname
    self.interactive_user = interactive_user
    self._ca_cert_chain = None

  def _AuthFunction(self):
    """Returns (username, password) to HttpRpcServer."""
    if not self.interactive_user:
      raise SimianClientError('UAuth: Requires password, no interactive user')

    user = '%s@google.com' % getpass.getuser()
    password = getpass.getpass('%s password: ' % user)
    return (user, password)

  def Login(self):
    """Login to /uauth.

    Returns:
      cookie string ready to be set into http Cookie header
    """
    # populate the certificates globally in HTTPSMultiBodyConnection
    # to avoid trying to hook its instantiation by urllib2.
    HTTPSMultiBodyConnection.SetCACertChain(self._ca_cert_chain)
    s = AppEngineHttpRpcServer(
        self.hostname,
        self._AuthFunction,
        None,
        'ah',
        save_cookies=True,
        secure=True)

    response = s.Send('/uauth')

    # Step 3 - load the response
    auth1 = auth_client.AuthSimianClient()
    auth1.Input(t=response)

    if not auth1.AuthStateOK():
      raise SimianClientError('UAuth: Invalid response: %s' % response)

    token_name = response
    output = None

    for cookie in s.cookie_jar:
      if cookie.domain == self.hostname:
        if cookie.name == token_name:
          if cookie.secure:
            suffix = 'secure'
          output = '%s=%s; %s; httponly;' % (cookie.name, cookie.value, suffix)

    if not output:
      raise SimianClientError('UAuth: No cookies from /uauth')

    return output

  def SetCACertChain(self, certs):
    """Set the CA certificate chain to verify SSL server certs.

    Args:
      certs: str, one or more X509 certificates concatenated after
        another
    """
    self._ca_cert_chain = certs


class HttpsAuthClient(HttpsClient):
  """Https client with support for authentication."""

  CLIENT_SSL_PATH = CLIENT_SSL_PATH
  PUPPET_CERTS = 'certs'
  PUPPET_PRIVATE_KEYS = 'private_keys'
  PUPPET_CA_CERT = 'ca.pem'
  FACTER_CACHE_OSX_PATH = '/Library/Managed Installs/facter.cache'
  FACTER_CACHE_DEFAULT_PATH = None  # disabled
  FACTER_CACHE_TIME = datetime.timedelta(hours=3)

  def __init__(self, *args, **kwargs):
    super(HttpsAuthClient, self).__init__(*args, **kwargs)
    self._auth1 = None
    self._cookie_token = None
    self._LoadCACerts()
    self._LoadCertSubjectLists()
    self._PlatformSetup()

  def _LoadCACerts(self):
    """Load CA certificates."""
    logging.debug('_LoadCACerts()')
    certs = self.GetSystemRootCACertChain()
    self.SetCACertChain(certs)

  def _LoadCertSubjectLists(self):
    """Load a predefined lists of cert subjects."""
    logging.debug('_LoadCertSubjectLists()')
    self._cert_valid_subjects = auth_settings.SERVER_CERT_VALID_SUBJECTS
    self._cert_require_subjects = auth_settings.SERVER_CERT_REQUIRE_SUBJECTS

  def _PlatformSetup(self):
    """Platform specific instance setup."""
    if platform.system() == 'Darwin':
      self.FACTER_CACHE_PATH = self.FACTER_CACHE_OSX_PATH
    else:
      self.FACTER_CACHE_PATH = self.FACTER_CACHE_DEFAULT_PATH

  def GetSystemRootCACertChain(self):
    """Load system supplied root CA certs.

    Returns:
      str, all x509 root ca certs, or '' if none can be found
    """
    contents = auth_settings.ROOT_CA_CERT_CHAIN_PEM
    if contents:
      logging.debug('Got root CA  cert chain: %s', contents)
      return contents
    else:
      return ''

  def _AdjustHeaders(self, headers):
    """Adjust headers before sending request."""
    if self._cookie_token:
      headers['Cookie'] = self._cookie_token

  def _SudoExec(self, argv, expect_rc=None):
    """Run an argv list with sudo.

    Args:
      argv: list, arguments to exec, argv[0] is binary
      expect_rc: int, optional, expected return code from exec
    Returns:
      (str stdout output, str stderr output)
    Raises:
      SudoExec: if an expect_* condition was not met
    """
    # NOTE(user): sudo 1.6.8p12 on OS X 10.5.8 doesn't understand the '--'
    # argument to stop parsing args.  Instead we do this evilness to enforce
    # a fully qualified command as first arg, which will clue sudo in to
    # pass the rest of args to the called program.
    if not argv[0].startswith('/'):
      raise SudoExecError(
          'First argument must have absolute path to run: %s' % argv[0])

    _argv = ['/usr/bin/sudo']  # better would be [sudo, '--']
    _argv.extend(argv)

    logging.info('Executing sudo: %s', ' '.join(_argv))
    p = subprocess.Popen(
        _argv, shell=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    rc = p.wait()

    output = stdout

    if expect_rc is not None:
      if rc != expect_rc:
        raise SudoExecError(
            'Sudo exec %s: rc %d != %d' % (_argv, rc, expect_rc))

    return (stdout, stderr)

  def _LoadFile(self, filename, requires_root=False, sudo_ok=False):
    """Load a filename's contents into a string.

    Args:
      filename: str, file to load
      requires_root: bool, optional, whether root is required to read
      sudo_ok: bool, optional, whether sudo may be used for root file access
    Returns:
      string file contents
    """
    if requires_root and os.getuid() != 0 and sudo_ok:
      (s, unused) = self._SudoExec(['/bin/cat', filename], expect_rc=0)
    else:
      f = open(filename, 'r')
      s = f.read()
      f.close()
    return s

  def _IsFile(self, filename, requires_root=False, sudo_ok=False):
    """Check if a file exists and is a file.

    Args:
      filename: str, filename to check
      requires_root: bool, optional, whether root is required to read
      sudo_ok: bool, optional, whether sudo may be used for root file access
    Returns:
      bool, True if the file exists
    """
    if requires_root and os.getuid() != 0 and sudo_ok:
      try:
        # the path location of bash is more standard than that of test(1)
        self._SudoExec(
            ['/bin/bash', '-c', '[ -f %s ]' % filename],
            expect_rc=0)
        return True
      except SudoExecError:
        return False
    else:
      return os.path.isfile(filename)


  def CacheFacterContents(self, open_fn=open):
    """Run facter to cache its contents, and also return them.

    Args:
      open_fn: func, optional, supply an open() function
    Returns:
      dict, facter contents (which have now also been cached)
    Raises:
      FacterError: if an error occurs when loading or validating facter
    """
    facts = {}

    logging.debug('CacheFacterContents()')
    try:
      stdout, unused_stderr = self._SudoExec(FACTER_CMD, expect_rc=0)
    except SudoExecError, e:
      logging.debug('CacheFacterContents(): could not run facter: %s', str(e))
      raise FacterError(str(e))

    # Iterate over the facter output and create a dictionary of the output
    lines = stdout.splitlines()
    for line in lines:
      (key, unused_sep, value) = line.split(' ', 2)
      value = value.strip()
      facts[key] = value

    logging.debug('CacheFacterContents(): read facter')


    if self.FACTER_CACHE_PATH:
      try:
        f = open_fn(self.FACTER_CACHE_PATH, 'w')
      except IOError:
        return facts

      Pickle.dump(facts, f)
      f.close()
      logging.debug(
          'CacheFacterContents(): wrote cache %s', self.FACTER_CACHE_PATH)

    return facts

  def GetFacter(self, open_fn=open):
    """Return facter contents.

    Args:
      open_fn: func, optional, supply an open() function
    Returns:
      dict, facter contents
    """
    now = datetime.datetime.now()
    facter = {}

    if self.FACTER_CACHE_PATH:
      try:
        st = os.stat(self.FACTER_CACHE_PATH)
        # if we are root, and the writer of the cache was not root, OR
        # if we are not root, the cache was not written by root, and
        # the cache was not written by ourselves
        if (os.geteuid() == 0 and st.st_uid != 0) or (
            os.geteuid() != 0 and st.st_uid != 0 and os.geteuid() != st.st_uid):
          # don't trust this file.  be paranoid.
          logging.debug('GetFacter: Untrusted facter cache, ignoring')
          cache_mtime = datetime.datetime.fromtimestamp(0)
        else:
          cache_mtime = datetime.datetime.fromtimestamp(st.st_mtime)
          logging.debug('GetFacter: facter cache mtime is %s', cache_mtime)
      except OSError, e:
        cache_mtime = datetime.datetime.fromtimestamp(0)

      if now - cache_mtime < self.FACTER_CACHE_TIME:
        try:
          logging.debug('GetFacter: reading recent facter cache')
          f = open_fn(self.FACTER_CACHE_PATH, 'r')
          facter = Pickle.load(f)
          f.close()
          logging.debug('GetFacter: read %d entities', len(facter))
        except (ImportError, EOFError, IOError, Pickle.UnpicklingError), e:
          logging.debug('GetFacter: error %s', str(e))
          facter = {}

    if not facter:
      facter = self.CacheFacterContents(open_fn=open_fn)

    return facter

  def _GetPuppetSslDetails(self, cert_fname=None, interactive_user=False):
    """Get Puppet SSL details.

    Args:
      cert_fname: str, optional, certification filename.
      interactive_user: bool, optional, default False,
        True if the client user an interactive user who can be prompted
        for auth.
    Returns:
      dict = {
          'cert': str, X509 format client certificate in PEM format,
          'ca_cert': str, X509 format CA certificate in PEM format,
          'priv_key': str, X509 format private key in PEM format,
          'cn': str, commonName of this client's certificate
      }
      or {} if the details cannot be read.
    """
    # TODO(user,user): unit test the puppet ssl cert harvesting functions.
    logging.debug('_GetPuppetSslDetails(%s)', cert_fname)
    certs_path = os.path.join(self.CLIENT_SSL_PATH, self.PUPPET_CERTS)

    best_cert = None
    priv_key = False
    output = {}
    cert_name = None

    if not cert_fname:  # if cert filename is not passed, check facter.
      try:
        facts = self.GetFacter()
      except FacterError:
        # don't give up, facter fails from time to time.
        facts = {}
      cert_name = facts.get('certname', None)
      if cert_name:
        cert_name = cert_name.strip()
        logging.debug('Certname from facter: "%s"', cert_name)
        cert_name = cert_name.lower()
        cert_fname = '%s.pem' % cert_name
      else:
        logging.debug('Error obtaining certname from facter')
        cert_fname = None

    if cert_fname:
      try:
        # attempt to get the cert passed as cert_fname,
        # or returned from facter.
        self._ValidatePuppetSslCert(certs_path, cert_fname)
        best_cert = cert_fname
      except PuppetSslCertError:
        # could not harvest the cert facter tells us to use, look for others.
        logging.error('Failed to harvest Puppet SSL cert facter specified.')

    if not best_cert:
      best_cert = self._GetNewestPuppetSslCert()

    # found, using the same filename look for the private cert.
    if best_cert:
      cn = best_cert.rsplit('.', 1)[0]
      priv_key = os.path.join(
          self.CLIENT_SSL_PATH, self.PUPPET_PRIVATE_KEYS, best_cert)
      logging.debug('_GetPuppetSslDetails priv should be %s', priv_key)

      # is it there?
      if self._IsFile(priv_key, requires_root=True, sudo_ok=interactive_user):
        output['cn'] = cn
        output['cert'] = self._LoadFile(os.path.join(
            self.CLIENT_SSL_PATH, self.PUPPET_CERTS, best_cert))
        output['priv_key'] = self._LoadFile(
            priv_key, requires_root=True, sudo_ok=interactive_user)
      else:
        logging.debug('_GetPuppetSslDetails not IsFile %s', priv_key)

    logging.info('Output = %s', output)
    return output

  def _ValidatePuppetSslCert(self, cert_dir_path, cert_fname):
    """Validates and returns true if a given Puppet SSL cert is valid.

    Args:
      cert_dir_path: str path to cert dir.
      cert_fname: str filename of the cert.
    Returns:
      Boolean, True if the cert is validated.
    Raises:
      PuppetSslCertError: there was an error reading the cert.
    """
    try:
      cert_path = os.path.join(cert_dir_path, cert_fname)
      logging.debug('_ValidatePuppetSslCert: %s', cert_path)
      f = open(cert_path, 'r')
      s = f.read(10240)
      f.close()
      x = x509.LoadCertificateFromPEM(s)
      if x.GetIssuer() != auth_settings.REQUIRED_ISSUER:
        msg = 'Skipping cert %s, unknown issuer' % cert_fname
        logging.debug(msg)
        raise PuppetSslCertError(msg)
    except IOError, e:
      logging.debug('Skipped cert %s, IO Error %s', cert_fname, str(e))
      raise PuppetSslCertError(str(e))
    except OSError, e:
      logging.debug('Skipped cert %s, OS Error %s', cert_fname, str(e))
      raise PuppetSslCertError(str(e))
    except x509.Error, e:
      logging.debug('Skipped cert %s, x509 error %s', cert_fname, str(e))
      raise PuppetSslCertError(str(e))

    return True

  def _GetNewestPuppetSslCert(self):
    """Harvests the newest Puppet SSL cert in the public certs directory.

    This directory is world readable so no increased privileges will be
    required.

    Returns:
      str newest cert filename, or None if none were found.
    """
    newest_cert = None
    newest_cert_timestamp = None
    certs_path = os.path.join(self.CLIENT_SSL_PATH, self.PUPPET_CERTS)
    certs = os.listdir(certs_path)
    logging.debug(
        '_GetNewestPuppetSslCert found certs %s', ' '.join(certs))
    for cert_fname in certs:
      if cert_fname != self.PUPPET_CA_CERT and cert_fname.endswith('.pem'):
        try:
          self._ValidatePuppetSslCert(certs_path, cert_fname)
        except PuppetSslCertError:
          continue

        cert_timestamp = os.path.getmtime(os.path.join(certs_path, cert_fname))
        if not newest_cert_timestamp or cert_timestamp > newest_cert_timestamp:
          logging.debug(
              '_GetPuppetSslDetails found cert %s with timestamp %s',
              cert_fname, cert_timestamp)
          newest_cert_timestamp = cert_timestamp
          newest_cert = cert_fname
        else:
          logging.debug(
              '_GetPuppetSslDetails skipping cert %s with older timestamp %s',
              cert_fname, cert_timestamp)
        # don't break here; need to exhaustively check the dir for newest cert.
    return newest_cert

  def _InitializeAuthClass(self, interactive_user=False, puppet_ssl=True):
    """Instantiate and configure an Auth1Client class.

    Args:
      interactive_user: bool, optional, default False,
        True if the client user an interactive user who can be prompted
        for auth.
      puppet_ssl: bool, optional, default True,
        True if the client should obtain SSL certs from Puppet
    Raises:
      SimianClientError: If SSL details from Puppet could not be harvested
    """
    if self._auth1 is not None:
      return

    auth1 = auth_client.AuthSimianClient()

    if puppet_ssl:
      o = self._GetPuppetSslDetails(interactive_user=interactive_user)
      if not o:
        raise SimianClientError('Could not obtain SSL details')

      auth1.LoadSelfKey(o['priv_key'])
      auth1.LoadSelfCert(o['cert'])

    self._auth1 = auth1

  def DoUAuth(self):
    """Do UAuth authentication."""
    interactive_user = os.isatty(sys.stdin.fileno())

    ua = UAuth(hostname=self.netloc, interactive_user=interactive_user)
    ua.SetCACertChain(self._ca_cert_chain)
    token = ua.Login()

    if not token:
      raise SimianClientError('No token supplied on cookie')

    self._cookie_token = token

  def DoSimianAuth(self, interactive_user=None):
    """Do Simian authentication.

    Args:
      interactive_user: bool, optional, default based on current tty,
        True if the client user an interactive user who can be prompted
        for auth.
    Raises:
      SimianServerError: an error occurs on the server
      SimianClientError: an error occurs on the client
    """
    if interactive_user is None:
      interactive_user = os.isatty(sys.stdin.fileno())

    self._InitializeAuthClass(interactive_user)

    # Step 0 - acquire a client nonce
    self._auth1.Input()
    cn = self._auth1.Output()

    # Step 1 - send client nonce to server
    response = self.Do('POST', '/auth', {'n': cn})

    # Step 1 return - look at server message output
    if response.status != 200:
      raise SimianServerError(
          'Auth step 1: %d %s' % (response.status, response.body))

    self._auth1.Input(m=response.body)
    o = self._auth1.Output()
    if not o:
      raise SimianClientError('Auth error: %s' % (
          ' '.join(self._auth1.ErrorOutput())))

    # Step 2 - send signed message to server
    response = self.Do('POST', '/auth', {'s': o['s'], 'm': o['m']})

    # Step 2 return - verify
    if response.status != 200:
      raise SimianServerError('Auth step 2')

    # Step 3 - load response
    self._auth1.Input(t=response.body)

    if not self._auth1.AuthStateOK():
      raise SimianClientError('Auth failed: %s' % (
          ' '.join(self._auth1.ErrorOutput())))

    # Success
    logging.info('headers = %s', response.headers)

    tokens = response.headers.get('set-cookie', None)
    if tokens is None:
      raise SimianClientError('No token supplied on cookie')

    tokens = tokens.split(',')  # split multiple cookies
    for token in tokens:
      if token.startswith(auth_settings.AUTH_TOKEN_COOKIE):
        self._cookie_token = token
        logging.debug('Found cookie token: %s', token)
        break

    if self._cookie_token is None:
      raise SimianClientError('No recognizable token found in cookies')


class SimianClient(HttpsAuthClient):
  """Client to connect to Simian server."""

  def __init__(self, hostname=None, port=None, root_ok=False):
    if hostname is None:
      hostname = SERVER_HOSTNAME
      self._default_hostname = True
    else:
      self._default_hostname = False
    if port is None:
      port = SERVER_PORT

    logging.debug(
        'SimianClient.__init__(%s [default=%s], %s, %s)',
        hostname, self._default_hostname, port, root_ok)

    self._user = self._GetLoggedOnUser()
    if self._user == 'root' and not root_ok:
      raise SimianClientError('Simian client must not be run as root!')

    super(SimianClient, self).__init__(hostname, port)

  def IsDefaultHostClient(self):
    """Returns True if the client was initialized with default hostname."""
    return self._default_hostname

  def _SimianRequest(
      self, method, url, body=None, headers=None, output_filename=None,
      full_response=False):
    """Make a request and return the body if successful.

    Args:
      method: str, HTTP method to use, like GET or POST.
      url: str, url to connect to, like '/foo/1'
      body: str or file or dict, optional, body of request
      headers: optional dict headers to send with the request.
      output_filename: str, optional, filename to write response body to
      full_response: bool, default False, return response object
    Returns:
      if output_filename is not supplied:
        if full_response is True:
          Response instance
        else:
          str, body received over http
      otherwise:
        None
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    response = self.Do(
        method, url, body=body, headers=headers,
        output_filename=output_filename)

    if response.IsSuccess():
      if not full_response:
        return response.body
      else:
        return response
    else:
      raise SimianServerError(response.status, response.reason)

  def _SimianRequestRetry(
      self, method, url, retry_on_status, body=None, headers=None,
      output_filename=None, full_response=False, attempt_times=3):
    """Make a request, retry if not successful, return the body if successful.

    Args:
      method: str, HTTP method to use, like GET or POST.
      url: str, url to connect to, like '/foo/1'
      retry_on_status: list, of int status codes to retry upon receiving
      body: str or file or dict, optional, body of request
      headers: optional dict of headers to send with the request.
      output_filename: str, optional, filename to write response body to
      full_response: bool, default False, return response object
      retry_times: int, default 3, how many times to retry
    Returns:
      if output_filename is not supplied:
        if full_response is True:
          Response instance
        else:
          str, body received over http
      otherwise:
        None
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    n = 0
    while n < attempt_times:
      logging.debug('SimianRequestRetry: try #%d %s %s', n, method, url)
      time.sleep(n * 5)
      try:
        response = None
        last_exc = None
        response = self._SimianRequest(
            method, url, body=body, headers=headers,
            output_filename=output_filename, full_response=True)
        if response.status not in retry_on_status:
          break
      except SimianServerError, e:
        last_exc = e
        if e.args[0] not in retry_on_status:
          raise e
      n += 1

    if response is not None:
      if response.IsSuccess() and response.status not in retry_on_status:
        if full_response:
          return response
        else:
          return response.body

    if last_exc is not None:
      raise last_exc
    elif response is not None:
      raise SimianServerError(response.status, response.reason)

  def _GetLoggedOnUser(self):
    """Returns the username of the logged on user."""
    if sys.platform == 'win32':
      return os.getenv('USERNAME')
    else:
      return os.getenv('LOGNAME')

  def _SimianFormUpload(self, url, name, params, input_filename, input_file):
    """Make a form/multipart POST request and return the body if successful.

    Args:
      url: str, url to connect to, like '/foo/1'
      name: str, name of file being uploaded
      params: dict of params to send with the request.
      input_filename: as DoMultipart()
      input_file: as DoMultipart()
    Returns:
      Response object if the request did not result in an error
    Raises:
      SimianServerError: if the Simian server returned an error
    """
    name = str(name.encode('utf-8'))
    new_params = params.copy()
    new_params['name'] = name
    # TODO(user): the following injects a non-fqdn username, which is
    # inconsistent with the rest of usernames used.
    new_params['user'] = self._user
    for k, v in new_params.iteritems():
      if type(v) is unicode:
        new_params[k] = str(v.encode('utf-8'))
    response = self.DoMultipart(
        url, new_params,
        name,
        input_filename=input_filename,
        input_file=input_file)

    if not response.IsError():
      return response
    else:
      raise SimianServerError(response.status, response.reason)

  def GetCatalog(self, name):
    """Get a catalog."""
    return self._SimianRequest('GET', '/catalog/%s' % name)

  def GetManifest(self, name):
    """Get a manifest."""
    return self._SimianRequest('GET', '/manifest/%s' % name)

  def GetPackage(self, name, output_filename=None):
    """Get a package.

    Args:
      name: str, package name
      output_filename: str, optional, filename to write response body to
    """
    return self._SimianRequest(
        'GET', '/pkgs/%s' % urllib.quote(name), 
        output_filename=output_filename)

  def PutPackage(self, filename, params, input_filename=None, input_file=None):
    """Put a package file contents.

    Read the documentation at
        http://code.google.com/
            appengine/docs/python/tools/webapp/blobstorehandlers.html

    for more information about why this method looks strange.  BlobStore
    upload requires a multipart/form POST to a dynamic URL.

    Args:
      filename: str, package filename
      params: dict of params to send with the request.
      input_filename: str, optional, filename to upload
      input_file: file, optional, file handle to read from
    Returns:
      str UUID for the uploaded payload
    Raises:
      SimianServerError: if an error occured on the Simian server
      SimianClientError: if an error occured on the this client
    """
    if not input_file and not input_filename:
      raise Error('Must supply input_file or input_filename')

    # obtain the URL to POST to
    logging.debug('Getting POST URL....')
    post_url = self._SimianRequest('GET', URL_UPLOADPKG)
    logging.debug('Received POST URL: %s', post_url)
    (scheme, netloc, path, query, fragment) = urlparse.urlsplit(post_url)

    if netloc != self.netloc:
      raise SimianClientError(
          'Upload package URL is different host: %s (%s)' % (
              netloc, self.netloc))

    logging.debug('Uploading package...')
    # send the file contents
    post_url = path
    response = self._SimianFormUpload(
        post_url, filename, params,
        input_file=input_file, input_filename=input_filename)

    # upon success OR a controlled failure a redirect will occur
    redirect_url = response.headers.get('location', None)
    (scheme, netloc, path, query, fragment) = urlparse.urlsplit(redirect_url)
    redirect_url = '%s?%s' % (path, query)

    if not response.IsRedirect() or not redirect_url:
      # something happened which the server did not handle properly
      raise SimianClientError(
          ('Unexpected response from upload: %s' % str(response)))

    # return the resulting blobstore ID
    result = self._SimianRequest('GET', redirect_url)
    return result

  def GetPackageInfo(self, filename, get_hash=False):
    """Get package info.

    Args:
      filename: str, name of packageinfo
      get_hash: bool, default False, request that the server include
        a X-Pkgsinfo-Hash with the response, a sha256 hash of the pkginfo.
    Returns:
      if not request_hash, str pkginfo XML
      if request_hash, tuple of (str sha256 hash, str pkginfo XML)
    """
    url = '/pkgsinfo/%s' % urllib.quote(filename)
    if get_hash:
      url = '%s?hash=1' % url

    response = self._SimianRequest('GET', url, full_response=True)

    if get_hash:
      if not 'x-pkgsinfo-hash' in response.headers:
        logging.debug(
            'GET %s returned headers = %s', url, str(response.headers))
        raise SimianServerError('No hash was supplied with pkginfo')
      return response.headers['x-pkgsinfo-hash'], response.body
    else:
      return response.body

  def PutPackageInfo(
      self, filename, pkginfo, catalogs=None, manifests=None,
      install_types=None, got_hash=None):
    """Put new/updated package info.

    Args:
      filename: str unique filename for pkginfo.
      pkginfo: str XML pkginfo.
      catalogs: optional, list of str catalogs to target.
      install_types: optional, list of str install types.
      got_hash: optional, str, sha256 hash of pkginfo retrieved earlier.
        if supplied, the server will only update the new pkginfo if the
        hash for the current pkginfo on the server matches this hash.
    Returns:
      str body from response.
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    filename = urllib.quote(filename)
    pkginfo = pkginfo.encode('utf-8')
    opts = []
    if catalogs:
      opts.append('catalogs=%s' % ','.join(catalogs))
    if manifests:
      opts.append('manifests=%s' % ','.join(manifests))
    if install_types:
      opts.append('install_types=%s' % ','.join(install_types))
    if got_hash:
      opts.append('hash=%s' % got_hash)
    url = '/pkgsinfo/%s?%s' % (
        filename, '&'.join(opts))
    return self._SimianRequest('PUT', url, pkginfo)

  def DeletePackage(self, filename):
    """Deletes a package.

    Note: this also deletes the pkginfo associated with the package.

    Args:
      filename: str filename of the package to delete.
    Returns:
      str body from response.
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    return self._SimianRequest('POST', '/deletepkg', {'filename': filename})

  def DownloadPackage(self, filename):
    """Downloads a package.

    Writes the package with the same filename into the current directory.

    Args:
      filename: str filename of the package to download.
    Returns:
      None
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    return self._SimianRequest(
        'GET', '/pkgs/%s' % urllib.quote(filename), 
        output_filename=filename)

  def _IsPackageUploadNecessary(self, filename, upload_pkginfo):
    """Returns True if the package file should be uploaded.

    This method helps the client decide whether to upload the entire package
    and package info, or just new package info.  It compares the sha256 hash
    of the existing package on the server with the one of the package file
    which would potentially be uploaded.  If the existing package info is
    not obtainable or not parseable the hash value cannot be compared, so
    True is returned to force an upload.

    Args:
      filename: str, package filename
      upload_pkginfo: package info of package being uploaded
    Returns:
      True if the package file and package info should be uploaded
      False if the package file is same, so just upload package info
    """
    return True

  def UploadPackage(
      self, filename, description, display_name, catalogs, manifests,
      install_types, pkginfo):
    """Uploads a Munki PackageInfo plist along with a Package.

    Args:
      filename: str file name to upload.
      description: str description.
      display_name: str human readable display name.
      catalogs: list of str catalog names.
      manifests: list of str manifest names.
      install_types: list of str install types.
      pkginfo: str package info.
    Returns:
      Tuple. (Str response body from upload, filename,
              list of catalogs, list of manifests)
    """
    file_path = filename
    filename = os.path.basename(filename)  # filename should be name only
    if not manifests:
      manifests = []

    if self._IsPackageUploadNecessary(file_path, pkginfo):
      params = {
          'pkginfo': pkginfo,
          'catalogs': ','.join(catalogs),
          'manifests': ','.join(manifests),
          'install_types': ','.join(install_types),
      }
      response = self.PutPackage(filename, params, input_filename=file_path)
    else:
      response = self.PutPackageInfo(
          filename, pkginfo, catalogs, manifests, install_types)

    return response, filename, catalogs, manifests

  def ListPackages(self, install_types=None, catalogs=None):
    """Gets a list of all packages of given install_types and catalogs.

    Args:
      install_types: list of string install types.
      catalogs: list of string catalogs.
    Returns:
      str body from response.
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    query = []
    if install_types:
      query.append('install_types=%s' % install_types)
    if catalogs:
      query.append('catalogs=%s' % catalogs)
    query = '&'.join(query)
    return self._SimianRequest('GET', '/pkgsinfo/?%s' % query)

  def PostReport(self, report_type, params, feedback=False):
    """Post a report to the server.

    Args:
      report_type: str, like 'install_report'
      params: dict, parameters to pass
      feedback: bool, default False, request feedback response from server
    Returns:
      str body from response
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    body = urllib.urlencode(params, doseq=True)
    body = '_report_type=%s&%s' % (report_type, body)
    if feedback:
      body = '%s&_feedback=1' % (body)
    return self._SimianRequestRetry('POST', '/reports', [500], str(body))

  def PostReportBody(self, body, feedback=False):
    """Post a pre-encoded report to the server.

    Args:
      body: str, the report body, urlencoded, it should contain
        a _report_type value!
      feedback: bool, default False, request feedback response from server
    Returns:
      str body from response
    Raises:
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    url = '/reports'
    if feedback:
      body = '%s&_feedback=1' % str(body)
    else:
      body = str(body)
    return self._SimianRequestRetry('POST', url, [500], body)


class SimianAuthClient(SimianClient):
  """Client perform authentication steps with Simian server."""

  def __init__(self, hostname=None, port=None, root_ok=None):
    super(SimianAuthClient, self).__init__(hostname, port, root_ok=True)

  def GetAuthToken(self):
    """Obtain a token from the server.

    Returns:
      token str
    """
    self.DoSimianAuth()
    return self._cookie_token

  def SetAuthToken(self, token):
    """Set the token.

    Args:
      token: str, token
    """
    self._cookie_token = str('%s=%s' % (auth_settings.AUTH_TOKEN_COOKIE, token))

  def LogoutAuthToken(self):
    """Given a token, make logout request to end that token.

    Returns:
      True if logout success, False if not
    """
    url = '/auth?logout=True'
    try:
      self._SimianRequest('GET', url)
      return True
    except SimianServerError:
      return False