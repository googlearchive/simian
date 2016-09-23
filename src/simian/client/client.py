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
#
#

"""Module containing classes to connect to Simian as a client."""




import datetime
import httplib
import logging
import mimetools
import os
import platform
import subprocess
import sys
import tempfile
import time
import urllib
import urlparse
import warnings

from M2Crypto import SSL
from M2Crypto.SSL import Checker


from simian.auth import x509
from simian import auth
from simian import settings
from simian.auth import client as auth_client
from simian.auth import util

warnings.filterwarnings(
    'ignore', '.* md5 module .*', DeprecationWarning, '.*', 0)

# seek constants moved from posixfile(2.4) to os(2.5+)
if sys.version_info[0] <= 2 and sys.version_info[1] <= 4:
  warnings.filterwarnings(
      'ignore', '', DeprecationWarning, 'posixfile', 0)
  import posixfile as _stdio  # pylint: disable=g-import-not-at-top
else:
  import os as _stdio  # pylint: disable=g-import-not-at-top,reimported


DEFAULT_HTTP_ATTEMPTS = 4
DEFAULT_RETRY_HTTP_STATUS_CODES = frozenset([500, 502, 503, 504])
SERVER_HOSTNAME = settings.SERVER_HOSTNAME
SERVER_PORT = settings.SERVER_PORT
AUTH_DOMAIN = settings.AUTH_DOMAIN
CLIENT_SSL_PATH = settings.CLIENT_SSL_PATH
SEEK_SET = _stdio.SEEK_SET
SEEK_CUR = _stdio.SEEK_CUR
SEEK_END = _stdio.SEEK_END
DEBUG = False
if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)
URL_UPLOADPKG = '/uploadpkg'

_SSL_VERSION = 'sslv23'
_CIPHER_LIST = None


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
      body: str, optional, body of the response
      headers: dict or list, like
          {'Content-type': 'foo'} or
          [('Content-type', 'foo')]
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


class MultiBodyConnection:  # pylint: disable=g-old-style-class,no-init
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
    # NOTE(user): if you need extreme amounts of http debugging uncomment
    # the following line:
    # self.debuglevel = 9

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
    # note python >=2.7 httplib now offers this functionality for us,
    # but we are continuing to do it ourselves.

    httplib.HTTPConnection.request(
        self, method, url, headers=headers)

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
    # Note: MultiBodyConnection has no __init__. Change this if it ever does.
    # MultiBodyConnection.__init__(*args, **kwargs)
    httplib.HTTPSConnection.__init__(self, *args, **kwargs)

  @classmethod
  def SetCACertChain(cls, certs):
    """Set the CA certificate chain to verify SSL peer (server) certs.

    NOTE:  Without having called this method to set a CA chain to verify
    against, calling connect() in the future will fail out of paranoia.

    Args:
      certs: str, one or more X509 certificates concatenated after
        another.  the only required delimiter between certs is that
        each cert start on a new line.  (but an empty line is not required)
    """
    cls._ca_cert_chain = certs

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
    # if openssl has verified this cert ok==1, otherwise 0.
    if ok != 1:
      subject = str(store.get_current_cert().get_subject())
      logging.debug(
          'IsValidCert() ok=%s cert=%s, returning 0', str(ok), subject)

    return (ok == 1) * 1

  def _LoadCACertChain(self, ctx):
    """Load a CA certificate chain into a SSL context.

    This includes setting the context verify modes to require certificate
    validation on the peer's cert.

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

    ctx = SSL.Context(_SSL_VERSION)
    if _CIPHER_LIST:
      ctx.set_cipher_list(_CIPHER_LIST)

    if hasattr(self, '_ca_cert_chain'):
      self._LoadCACertChain(ctx)
    else:
      raise SimianClientError('Missing CA certificate chain')

    logging.debug('SSL configuring with context')
    sock = SSL.Connection(ctx)
    logging.debug('SSL connect(%s)', server_address)
    try:
      sock.connect(server_address)
    except SSL.SSLError, e:
      raise SimianClientError('SSL error: %s' % str(e))
    except Checker.SSLVerificationError, e:
      raise SimianClientError('SSLVerificationError: %s' % str(e))

    logging.debug('SSL connected %s', server_address)
    self.sock = sock
    # Note we are dropping HTTP CONNECT tunnel support by not handling
    # _tunnel_* options here, see original HTTPConnection.connect().




class HttpsClient(object):
  """Connect to a http or https service.

  Defaults to https unless if overridden with a URL-style hostname,
  e.g. "http://...."
  """

  def __init__(self, hostname, port=None, proxy=None):
    self._LoadHost(hostname, port, proxy)
    self._progress_callback = None
    self._ca_cert_chain = None

  def SetProgressCallback(self, fn):
    self._progress_callback = fn

  def SetCACertChain(self, certs):
    """Set the CA certificate chain to verify SSL server certs.

    Args:
      certs: str, one or more X509 certificates concatenated after
        another
    """
    self._ca_cert_chain = certs

  def _LoadHost(self, hostname, port=None, proxy=None):
    """Load hostname and port to connect to.

    Args:
      hostname: str, like a URL or a hostname string.  Examples:
        'http://foo' 'http://foo:port' 'https://foo' 'foo:port' 'foo'
      port: int, optional, port to connect to, which will be overridden by
        any port specified in the hostname str.
      proxy: str, optional, "host:port" formatted HTTP proxy
    Raises:
      Error: if args are malformed
    """
    logging.debug('LoadHost(%s, %s)', hostname, port)

    # unicode causes problems later on the socket level. rid ourselves of it.
    hostname = str(hostname)
    if proxy is not None:
      proxy = str(proxy)
    elif proxy is None:
      if os.environ.get('HTTPS_PROXY'):
        proxy = str(os.environ['HTTPS_PROXY'])
      elif os.environ.get('http_proxy'):
        proxy = str(os.environ['http_proxy'])

    # note: defaulting to https when no scheme is given.
    if not hostname.startswith('http'):
      hostname = 'https://%s' % hostname

    (scheme, netloc, unused_path, unused_query, unused_frag
    ) = urlparse.urlsplit(hostname)

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

    self.proxy_hostname = None
    self.proxy_port = None
    self.proxy_use_https = False
    if proxy:
      u = urlparse.urlparse(proxy)
      if u.scheme in ['https', 'http']:
        self.proxy_use_https = u.scheme == 'https'
        (self.proxy_hostname, self.proxy_port) = urllib.splitport(u.netloc)
      else:
        (self.proxy_hostname, self.proxy_port) = urllib.splitport(proxy)
      if not self.proxy_port:
        raise Error('proxy does not specify port: %s', proxy)
      self.proxy_port = int(self.proxy_port)
      logging.debug('LoadHost(): proxy host = %s, proxy port = %s',
                    self.proxy_hostname, self.proxy_port)

  def _AdjustHeaders(self, unused_headers):
    """Adjust headers before a request.

    Intended for override in subclasses to inject headers.
    """
    return

  def _Connect(self):
    """Return a HTTPSConnection object.

    Returns:
      HTTPConnection object
    """
    conn_args = (self.hostname, self.port)
    if self.proxy_hostname:
      conn_args = (self.proxy_hostname, self.proxy_port)
      use_https = self.proxy_use_https
    else:
      use_https = self.use_https

    if use_https:
      conn = HTTPSMultiBodyConnection(*conn_args)
    else:
      conn = HTTPMultiBodyConnection(*conn_args)

    # NOTE(user): at this point it would be nice to copy our debug level
    # into the http connection instance with set_debuglevel().  however the
    # debug is printed to stdout, which will foul up our clients.

    if self._progress_callback is not None:
      conn.SetProgressCallback(self._progress_callback)

    if use_https:
      if self._ca_cert_chain is not None:
        conn.SetCACertChain(self._ca_cert_chain)

    try:
      conn.connect()
    except httplib.socket.error, e:
      raise SimianClientError('_Connect() httplib.socket.error: %s' % str(e))
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

    if headers is None:
      headers = {}
    if 'User-Agent' not in headers:
      headers['User-Agent'] = 'gzip'

    self._AdjustHeaders(headers)

    # smash url to str(), in case unicode has slipped in, which never
    # sends properly.
    conn.request(method, str(url), body=body, headers=headers)

  def _DoRequestResponse(
      self, method, url, body=None, headers=None, output_file=None):
    """Connect to hostname, make a request, obtain response.

    Args:
      method: str, like 'GET' or 'POST'
      url: str, url like '/foo.html', not 'http://host/foo.html'
      body: str or dict or file, optional, body to send with request
      headers: dict, optional, headers to send with request
      output_file: file, optional, file to write response body to
    Returns:
      Response instance
    Raises:
      HTTPError: if a connection level error occured
    """
    try:
      suffix = self.use_https * 's'
      logging.debug('Connecting to http%s://%s:%s',
                    suffix, self.hostname, self.port)
      conn = self._Connect()
      # if proxy is in use, request the full URL including host.
      if self.proxy_hostname:
        url = 'http%s://%s%s' % (self.use_https * 's', self.netloc, url)
      logging.debug('Requesting %s %s', method, url)
      self._Request(method, conn, url, body=body, headers=headers)
      logging.debug('Waiting for response')
      response = self._GetResponse(conn, output_file=output_file)
      logging.debug('Response status %d', response.status)
      return response
    except httplib.HTTPException, e:
      raise HTTPError(str(e))
    except IOError as e:
      raise HTTPError(str(e))

  def Do(
      self, method, url,
      body=None, headers=None, output_filename=None,
      retry_on_status=DEFAULT_RETRY_HTTP_STATUS_CODES,
      attempt_times=DEFAULT_HTTP_ATTEMPTS, _open=open):
    """Make a request and return the response.

    Args:
      method: str, like 'GET' or 'POST'
      url: str, url like '/foo.html', not 'http://host/foo.html'
      body: str or dict or file, optional, body to send with request
      headers: dict, optional, headers to send with request
      output_filename: str, optional, filename to write response body to
      retry_on_status: list, default (500, 502, etc.), int status codes to
          retry upon receiving.
      attempt_times: int, default 4, how many times to attempt the request
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

    n = 0
    while n < attempt_times:
      time.sleep(n * 5)
      n += 1
      logging.debug('Do(%s, %s) try #%d', method, url, n)
      try:
        response = self._DoRequestResponse(
            method, url, body=body, headers=headers, output_file=output_file)
      except HTTPError:
        logging.warning('HTTPError in Do(%s, %s)', method, url)
        if n == attempt_times:
          raise
      else:
        if response.status not in retry_on_status:
          break
        logging.warning('Retry status hit for Do(%s, %s)', method, url)

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
      Error: if input is invalid
      HTTPError: if a connection level error occured
    """
    if not input_filename and not input_file:
      raise Error('must supply input_filename or input_file')

    boundary = mimetools.choose_boundary()
    content_type = 'application/octet-stream'
    headers = {
        'Content-Type': 'multipart/form-data; boundary=%s' % boundary,
    }

    close_input_file = False
    if input_file is None:
      close_input_file = True
      input_file = open(input_filename, 'r')

    crlf = '\r\n'
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

    body.append(crlf.join(tmp_body))
    body.append(crlf)
    body.append(input_file)
    body.append(crlf)

    tmp_body = []
    for k, v in params.iteritems():
      tmp_body.append('--%s' % boundary)
      tmp_body.append(
          'Content-Disposition: form-data; name="%s"' % k)
      tmp_body.append('Content-type: text/plain; charset=utf-8')
      tmp_body.append('')
      tmp_body.append(v)

    body.append(crlf.join(tmp_body))
    body.append('%s--%s--%s' % (crlf, boundary, crlf))
    body.append(crlf)

    try:
      response = self.Do('POST', url, body=body, headers=headers)
    except:
      if close_input_file:
        input_file.close()
      raise

    if close_input_file:
      input_file.close()

    return response


class HttpsAuthClient(HttpsClient):
  """Https client with support for authentication."""

  CLIENT_SSL_PATH = CLIENT_SSL_PATH
  PUPPET_CERTS = 'certs'
  PUPPET_PRIVATE_KEYS = 'private_keys'
  PUPPET_CA_CERT = 'ca.pem'
  FACTER_CACHE_OSX_PATH = '/Library/Managed Installs/facter.cache'
  FACTER_CACHE_DEFAULT_PATH = None  # disabled

  def __init__(self, *args, **kwargs):
    super(HttpsAuthClient, self).__init__(*args, **kwargs)
    self._auth1 = None
    self._cookie_token = None
    self._LoadRootCertChain()
    self._PlatformSetup()
    self._LoadCaParameters()

  def _LoadRootCertChain(self):
    """Load CA certificates."""
    logging.debug('_LoadRootCertChain()')
    certs = self.GetSystemRootCACertChain()
    self.SetCACertChain(certs)

  def _PlatformSetup(self):
    """Platform specific instance setup."""
    if platform.system() == 'Darwin':
      self.facter_cache_path = self.FACTER_CACHE_OSX_PATH
    else:
      self.facter_cache_path = self.FACTER_CACHE_DEFAULT_PATH

  def _LoadCaParameters(self):
    """Load CA parameters from settings."""
    logging.debug('LoadCaParameters')
    self._ca_params = util.GetCaParameters(
        settings, omit_server_private_key=True)
    logging.debug('Loaded ca_params')

  def _AdjustHeaders(self, headers):
    """Adjust headers before a request.

    Override in subclasses.

    Args:
      headers: dict, headers that will be passed to a http request.
    """
    if self._cookie_token and headers is not None:
      headers['Cookie'] = self._cookie_token

  def GetSystemRootCACertChain(self):
    """Load system supplied root CA certs.

    Returns:
      str, all x509 root ca certs, or '' if none can be found
    """
    try:
      f = open(settings.ROOT_CA_CERT_CHAIN_PEM_PATH, 'r')
      contents = f.read()
    except (AttributeError, IOError):
      contents = None  # root CA cert chain is optional
    if contents:
      logging.debug('Got Root CA Cert Chain: %s', contents)
      return contents
    else:
      logging.warning('Root CA Cert Chain was EMPTY!')
      return ''

  def _SudoExec(self, argv, expect_rc=None):
    """Run an argv list with sudo.

    Args:
      argv: list, arguments to exec, argv[0] is binary
      expect_rc: int, optional, expected return code from exec
    Returns:
      (str stdout output, str stderr output)
    Raises:
      SudoExecError: if an expect_* condition was not met
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
      (s, unused_stderr) = self._SudoExec(['/bin/cat', filename], expect_rc=0)
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

  def GetFacter(self, open_fn=open):
    """Return facter contents.

    Args:
      open_fn: func, optional, supply an open() function
    Returns:
      dict, facter contents
    """
    if self.facter_cache_path is None:
      return {}

    if not os.path.isfile(self.facter_cache_path):
      logging.info('GetFacter: facter cache file does not exist.')
      return {}

    facter = {}
    use_facter_cache = False
    try:
      st = os.stat(self.facter_cache_path)
      # if we are root, and the writer of the cache was not root, OR
      # if we are not root, the cache was not written by root, and
      # the cache was not written by ourselves
      if (os.geteuid() == 0 and st.st_uid != 0) or (
          os.geteuid() != 0 and st.st_uid != 0 and os.geteuid() != st.st_uid):
        # don't trust this file.  be paranoid.
        logging.info('GetFacter: Untrusted facter cache, ignoring')
        use_facter_cache = False
      else:
        use_facter_cache = True
        cache_mtime = datetime.datetime.fromtimestamp(st.st_mtime)
        logging.debug('GetFacter: facter cache mtime is %s', cache_mtime)
    except OSError, e:
      logging.info('GetFacter: OSError from os.stat(): %s', str(e))
      use_facter_cache = False

    if use_facter_cache:
      try:
        logging.debug('GetFacter: reading recent facter cache')
        f = open_fn(self.facter_cache_path, 'r')
        facter = {}
        line = f.readline()
        while line:
          try:
            (key, unused_sep, value) = line.split(' ', 2)
            value = value.strip()
            facter[key] = value
          except ValueError:
            logging.info('GetFacter: ignoring facter cache line: %s', line)
          line = f.readline()
        f.close()
        logging.debug('GetFacter: read %d entities', len(facter))
      except (EOFError, IOError), e:
        logging.warning('GetFacter: error %s', str(e))
        facter = {}

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
    # TODO(user): unit test the puppet ssl cert harvesting functions.
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

    # NOTE(user):  There is a maximum size of a single syslog message
    # under OS X on Python (the exact value of which seems to depend on OS
    # X version)
    if 'headers' in output:
      logging.info('Output headers = %s', output['headers'])
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
    required_issuer = self._ca_params.required_issuer

    logging.debug(
        '_ValidatePuppetSslCert: required_issuer %s', required_issuer)

    try:
      cert_path = os.path.join(cert_dir_path, cert_fname)
      logging.debug('_ValidatePuppetSslCert: %s', cert_path)
      f = open(cert_path, 'r')
      s = f.read()
      f.close()
      x = x509.LoadCertificateFromPEM(s)

      issuer = x.GetIssuer()
      logging.debug('Looking at issuer %s', issuer)
      # Check issuer match.
      if issuer != required_issuer:
        # no match at all.
        msg = 'Skipping cert %s, unknown issuer' % cert_fname
        logging.warning(msg)
        logging.warning(
            'Expected: "%s" Received: "%s"', required_issuer, issuer)
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
      # Load the CA parameters after GetPuppetSslDetails figured out
      # which CA settings are optimal to use on this client.
      auth1.LoadCaParameters(settings)
      auth1.LoadSelfKey(o['priv_key'])
      auth1.LoadSelfCert(o['cert'])
    else:
      auth1.LoadCaParameters(settings)

    self._auth1 = auth1

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

    # Generate /auth URL
    auth_url = '/auth'
    if self._ca_params.ca_id:
      auth_url = '%s?ca_id=%s' % (auth_url, self._ca_params.ca_id)

    # Step 1 - send client nonce to server
    response = self.Do('POST', auth_url, {'n': cn})

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
    response = self.Do('POST', auth_url, {'s': o['s'], 'm': o['m']})

    # Step 2 return - verify
    if response.status != 200:
      raise SimianServerError('Auth step 2')

    # Step 3 - load response
    self._auth1.Input(t=response.body)

    if not self._auth1.AuthStateOK():
      raise SimianClientError('Auth failed: %s' % (
          ' '.join(self._auth1.ErrorOutput())))

    # Success
    self._cookie_token = self._GetAuthTokenFromHeaders(response.headers)

  def _GetAuthTokenFromHeaders(self, headers):
    """Parses headers dict to return string auth token.

    Args:
      headers: HTTP response headers in dict-like object.
    Returns:
      string Simian Auth Token.
    Raises:
      SimianClientError: no token was found.
    """
    sanitized_headers = headers.copy()
    del sanitized_headers['set-cookie']
    logging.info('headers = %s', sanitized_headers)

    tokens = headers.get('set-cookie', None)
    if tokens is None:
      raise SimianClientError('No token supplied on cookie')

    tokens = tokens.split(',')  # split multiple cookies
    for token in tokens:
      if token.startswith(auth.AUTH_TOKEN_COOKIE):
        logging.debug('Found cookie token.')
        return token

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
    Raises
      SimianServerError: if the Simian server returned an error (status != 200)
    """
    try:
      response = self.Do(
          method, url, body=body, headers=headers,
          output_filename=output_filename)
    except HTTPError, e:
      raise SimianServerError(str(e))

    if response.IsSuccess():
      if not full_response:
        return response.body
      else:
        return response
    else:
      raise SimianServerError(response.status, response.reason, response.body)

  def _GetLoggedOnUser(self):
    """Returns the username of the logged on user."""
    if sys.platform == 'win32':
      return os.getenv('USERNAME')
    else:
      return os.getenv('LOGNAME')

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
    Returns:
      See _SimianRequest
    """
    return self._SimianRequest(
        'GET', '/pkgs/%s' % urllib.quote(name),
        output_filename=output_filename)

  def GetPackageInfo(self, filename, get_hash=False):
    """Get package info.

    Args:
      filename: str, name of packageinfo
      get_hash: bool, default False, request that the server include
        a X-Pkgsinfo-Hash with the response, a sha256 hash of the pkginfo.
    Returns:
      if not request_hash, str pkginfo XML
      if request_hash, tuple of (str sha256 hash, str pkginfo XML)
    Raises:
      SimianServerError: if an error occured on the Simian server
    """
    url = '/pkgsinfo/%s' % urllib.quote(filename)
    if get_hash:
      url = '%s?hash=1' % url

    response = self._SimianRequest('GET', url, full_response=True)

    if get_hash:
      if 'x-pkgsinfo-hash' not in response.headers:
        logging.debug(
            'GET %s returned headers = %s', url, str(response.headers))
        raise SimianServerError('No hash was supplied with pkginfo')
      return response.headers['x-pkgsinfo-hash'], response.body
    else:
      return response.body

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

  def GetPackageMetadata(
      self, install_types=None, catalogs=None, filename=None):
    """Gets a list of all packages of given install_types and catalogs.

    Args:
      install_types: list of string install types.
      catalogs: list of string catalogs.
      filename: str filename of the package.
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
    if filename:
      query.append('filename=%s' % filename)
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
    return self._SimianRequest('POST', '/reports', str(body))

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
    return self._SimianRequest('POST', url, body)

  def UploadFile(self, file_path, file_type, _open=open):
    """Uploads a given log file to the server.

    Args:
      file_path: str, path of log file to upload.
      file_type: str, type of file being uploaded, like 'log'.
      _open: func, optional, default builtin open, to open file_path.
    """
    if os.path.isfile(file_path):
      logging.debug('UploadFile uploading file: %s', file_path)
      file_handle = _open(file_path, 'r')
      file_name = os.path.basename(file_path)
      url = '/uploadfile/%s/%s' % (file_type, file_name)
      try:
        self.Do('PUT', url, file_handle)
      finally:
        file_handle.close()
    else:
      logging.error('UploadFile file not found: %s', file_path)


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
    self._cookie_token = str('%s=%s' % (auth.AUTH_TOKEN_COOKIE, token))

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
