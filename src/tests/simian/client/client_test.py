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
"""client module tests."""

import httplib
import logging
import sys


from pyfakefs import fake_filesystem
import M2Crypto
import mock
import stubout

from google.apputils import app
from google.apputils import basetest

from simian import auth
from simian.client import client


class ClientModuleTest(basetest.TestCase):
  """Test the client module."""

  def testConstants(self):
    for a in [
        'SERVER_HOSTNAME', 'SERVER_PORT', 'AUTH_DOMAIN',
        'CLIENT_SSL_PATH', 'SEEK_SET', 'SEEK_CUR', 'SEEK_END',
        'DEBUG', 'URL_UPLOADPKG']:
      self.assertTrue(hasattr(client, a))


class MultiBodyConnectionTest(basetest.TestCase):
  """Test MultiBodyConnection class."""

  def setUp(self):
    super(MultiBodyConnectionTest, self).setUp()
    self.stubs = stubout.StubOutForTesting()
    self.mbc = client.MultiBodyConnection()

  def tearDown(self):
    super(MultiBodyConnectionTest, self).tearDown()
    self.stubs.UnsetAll()

  def testSetProgressCallback(self):
    """Test SetProgressCallback()."""
    fn = lambda x: 1

    self.assertFalse(hasattr(self.mbc, '_progress_callback'))
    self.mbc.SetProgressCallback(fn)
    self.assertEqual(self.mbc._progress_callback, fn)
    self.assertRaises(
        client.Error,
        self.mbc.SetProgressCallback, 1)

  def testProgressCallback(self):
    """Test _ProgressCallback()."""
    self.mbc._ProgressCallback(1, 2)

    self.mbc._progress_callback = mock.Mock()
    self.mbc._ProgressCallback(1, 2)

    self.mbc._progress_callback.assert_called_with(1, 2)

  @mock.patch.object(client.httplib.HTTPConnection, 'request')
  def testRequest(self, mock_request):
    """Test request()."""
    fs = fake_filesystem.FakeFilesystem()
    fake_os = fake_filesystem.FakeOsModule(fs)
    fake_open = fake_filesystem.FakeFileOpen(fs)

    file_name = '/f1'
    file_size = 10000
    f_body = 'x' * file_size
    fs.CreateFile(file_name, contents=f_body)
    fake_file = fake_open(file_name, 'r')
    self.stubs.Set(client, 'os', fake_os)

    method = 'GET'
    url = '/foo'
    body = ['hello', fake_file]
    content_length = len(body[0]) + file_size
    headers = {
        'Content-Length': content_length,
    }

    self.mbc._is_https = False

    self.mbc.send = mock.Mock()
    self.mbc._ProgressCallback = mock.Mock()

    inorder_calls = mock.Mock()
    inorder_calls.attach_mock(mock_request, 'request')
    inorder_calls.attach_mock(self.mbc.send, 'send')
    inorder_calls.attach_mock(self.mbc._ProgressCallback, '_ProgressCallback')

    self.mbc.request(method, url, body=body)

    inorder_calls.assert_has_calls([
        mock.call.request(self.mbc, method, url, headers=headers),
        mock.call._ProgressCallback(0, content_length),
        mock.call.send(body[0]),
        mock.call._ProgressCallback(len(body[0]), content_length),
        mock.call.send(f_body[:8192]),
        mock.call._ProgressCallback(len(body[0]) + 8192, content_length),
        mock.call.send(f_body[8192:]),
        mock.call._ProgressCallback(len(body[0]) + file_size, content_length),
        mock.call._ProgressCallback(len(body[0]) + file_size, content_length)])


class HTTPSMultiBodyConnectionTest(basetest.TestCase):
  def setUp(self):
    self.stubs = stubout.StubOutForTesting()
    self.hostname = 'foohost'
    self.mbc = client.HTTPSMultiBodyConnection(self.hostname)

  def tearDown(self):
    self.stubs.UnsetAll()

  def testParentClassRequestAssumption(self):
    """Test assumptions of parent class request()."""
    method = 'GET'
    url = '/foo'
    body = None
    headers = {}

    with mock.patch.object(
        client.httplib.HTTPConnection,
        '_send_request', return_value=-1) as mock_fn:
      c = client.httplib.HTTPConnection(self.hostname)
      self.assertEqual(None, c.request(method, url))

      mock_fn.assert_called_once_with(method, url, body, headers)

  @mock.patch.object(client.httplib.HTTPConnection, 'send', autospec=True)
  @mock.patch.object(client.httplib.HTTPConnection, 'endheaders')
  @mock.patch.object(client.httplib.HTTPConnection, 'putheader')
  @mock.patch.object(client.httplib.HTTPConnection, 'putrequest')
  def testParentClassSendRequestAssumptionEmptyBody(
      self, putrequest_mock, putheader_mock, endheaders_mock, send_mock):
    """Test assumptions of parent class _send_request()."""
    method = 'GET'
    url = '/foo'
    body1 = None
    headers = {'foo': 'bar'}

    inorder_calls = mock.Mock()
    inorder_calls.attach_mock(putrequest_mock, 'putrequest')
    inorder_calls.attach_mock(putheader_mock, 'putheader')
    inorder_calls.attach_mock(endheaders_mock, 'endheaders')
    inorder_calls.attach_mock(send_mock, 'send')

    # with a None body supplied, send() is never called.  on >=2.7
    # endheaders is still called with the body contents, even if they
    # are None.
    c = client.httplib.HTTPConnection(self.hostname)
    c._send_request(method, url, body1, headers)

    expected = [
        mock.call.putrequest(method, url),
        mock.call.putheader('foo', headers['foo'])
    ]
    if sys.version_info[0] >= 2 and sys.version_info[1] >= 7:
      expected.append(mock.call.endheaders(body1))
    else:
      expected.append(mock.call.endheaders())

    inorder_calls.assert_has_calls(expected)

  @mock.patch.object(client.httplib.HTTPConnection, 'send', autospec=True)
  @mock.patch.object(client.httplib.HTTPConnection, 'endheaders')
  @mock.patch.object(client.httplib.HTTPConnection, 'putheader')
  @mock.patch.object(client.httplib.HTTPConnection, 'putrequest')
  def testParentClassSendRequestAssumption(
      self, putrequest_mock, putheader_mock, endheaders_mock, send_mock):
    """Test assumptions of parent class _send_request()."""
    method = 'GET'
    url = '/foo'
    body2 = 'howdy'
    headers = {'foo': 'bar'}

    inorder_calls = mock.Mock()
    inorder_calls.attach_mock(putrequest_mock, 'putrequest')
    inorder_calls.attach_mock(putheader_mock, 'putheader')
    inorder_calls.attach_mock(endheaders_mock, 'endheaders')
    inorder_calls.attach_mock(send_mock, 'send')

    # with a body supplied, send() is called inside _send_request() on
    # httplib < 2.6. in >=2.7 endheaders() sends the body and headers
    # all at once.
    expected = [
        mock.call.putrequest(method, url),
        mock.call.putheader('Content-Length', str(len(body2))),
        mock.call.putheader('foo', headers['foo'])
    ]
    if sys.version_info[0] >= 2 and sys.version_info[1] >= 7:
      expected.append(mock.call.endheaders(body2))
    else:
      expected.append(mock.call.endheaders())
      expected.append(mock.send(body2))

    c = client.httplib.HTTPConnection(self.hostname)
    c._send_request(method, url, body2, headers)

    inorder_calls.assert_has_calls(expected)

  def testDirectSendTypes(self):
    """Test the DIRECT_SEND_TYPES constant for sane values."""
    self.assertTrue(type(self.mbc.DIRECT_SEND_TYPES) is list)

  @mock.patch.object(client.httplib.HTTPConnection, 'request')
  @mock.patch.object(client.httplib.HTTPConnection, 'send')
  def testRequestSimple(self, mock_send, mock_request):
    """Test request with one body element."""
    method = 'GET'
    url = '/foo'
    body = 'hello'
    headers = {
        'Content-Length': len(body),
        'Host': self.hostname,
    }

    self.mbc.request(method, url, body=body)

    mock_request.assert_called_once_with(
        self.mbc,
        method, url, headers=headers)
    mock_send.assert_called_once_with(body)

  @mock.patch.object(client.httplib.HTTPConnection, 'request')
  @mock.patch.object(client.httplib.HTTPConnection, 'send')
  def testRequestMultiString(self, send_mock, request_mock):
    """Test request() with multiple body string elements."""
    method = 'GET'
    url = '/foo'
    body = ['hello', 'there']
    headers = {
        'Content-Length': sum(map(len, body)),
        'Host': self.hostname,
    }
    for s in body:
      client.httplib.HTTPConnection.send(s).AndReturn(None)
    self.mbc.request(method, url, body=body)

    request_mock.assert_called_once_with(self.mbc, method, url, headers=headers)
    send_mock.assert_has_calls([mock.call(x) for x in body])

  @mock.patch.object(client.httplib.HTTPConnection, 'send')
  @mock.patch.object(client.httplib.HTTPConnection, 'request')
  def testRequestMultiMixed(self, request_mock, send_mock):
    """Test request() with multiple mixed body elements."""
    filepath = '/somefilename'
    f_body = 'there'
    fs = fake_filesystem.FakeFilesystem()
    fs.CreateFile(filepath, contents=f_body)
    fake_open = fake_filesystem.FakeFileOpen(fs)

    f = fake_open(filepath)
    method = 'GET'
    url = '/foo'
    body = ['hello', f]
    content_length = len(body[0]) + len(f_body)
    headers = {
        'Content-Length': content_length,
        'Host': self.hostname,
    }

    self.mbc.request(method, url, body=body)

    request_mock.assert_called_once_with(self.mbc, method, url, headers=headers)

    self.assertEqual(2, send_mock.call_count)
    send_mock.assert_has_calls([mock.call(body[0]), mock.call(f_body)])

  def testSetCACertChain(self):
    """Test SetCACertChain()."""
    self.mbc.SetCACertChain('foo')
    self.assertEqual(self.mbc._ca_cert_chain, 'foo')

  def testIsValidCert(self):
    """Test _IsValidCert()."""
    self.assertEqual(1, self.mbc._IsValidCert(1, 1))

  def testIsValidCertOkZero(self):
    """Test _IsValidCert()."""
    cert = mock.create_autospec(M2Crypto.X509.X509)
    cert_subject = mock.create_autospec(M2Crypto.X509.X509_Name)
    store = mock.create_autospec(M2Crypto.X509.X509_Store_Context)
    store.get_current_cert.return_value = cert
    cert.get_subject.return_value = cert_subject
    cert_subject.__str__.return_value = 'valid'

    self.assertEqual(0, self.mbc._IsValidCert(0, store))
    cert_subject.__str__.assert_called()

  @mock.patch.object(client.tempfile, 'NamedTemporaryFile', autospec=True)
  def testLoadCACertChain(self, named_temporary_file_mock):
    """Test _LoadCACertChain()."""
    temp_filepath = '/tmp/somefilename'
    fs = fake_filesystem.FakeFilesystem()
    fs.CreateFile(temp_filepath)
    fake_open = fake_filesystem.FakeFileOpen(fs)

    tf = fake_open(temp_filepath, 'w')
    named_temporary_file_mock.return_value = tf

    ctx = mock.create_autospec(M2Crypto.SSL.Context)
    ctx.load_verify_locations.return_value = 1
    cert_chain = 'cert chain la la ..'

    self.mbc._ca_cert_chain = cert_chain

    self.mbc._LoadCACertChain(ctx)

    self.assertEqual(cert_chain, fake_open(temp_filepath, 'r').read())

    # mock 2.0.0 incorrectly binds spec to calls
    ctx._spec_signature = None

    ctx.assert_has_calls([
        mock.call.load_verify_locations(cafile=tf.name),
        mock.call.set_verify(
            client.SSL.verify_peer | client.SSL.verify_fail_if_no_peer_cert,
            depth=9, callback=self.mbc._IsValidCert)])

  @mock.patch.object(client.tempfile, 'NamedTemporaryFile', autospec=True)
  def testLoadCACertChainWhenLoadError(self, named_temporary_file_mock):
    """Test _LoadCACertChain()."""
    temp_filepath = '/tmp/somefilename'
    fs = fake_filesystem.FakeFilesystem()
    fs.CreateFile(temp_filepath)
    fake_open = fake_filesystem.FakeFileOpen(fs)

    tf = fake_open(temp_filepath, 'w')
    named_temporary_file_mock.return_value = tf

    cert_chain = 'cert chain la la ..'

    self.mbc._ca_cert_chain = cert_chain

    ctx = mock.create_autospec(M2Crypto.SSL.Context)
    self.assertRaises(
        client.SimianClientError, self.mbc._LoadCACertChain, ctx)

    ctx.load_verify_locations.assert_called_once_with(cafile=tf.name)

    self.assertEqual(cert_chain, fake_open(temp_filepath, 'r').read())

  def testLoadCACertChainWhenNone(self):
    """Test _LoadCACertChain()."""
    self.assertRaises(
        client.SimianClientError, self.mbc._LoadCACertChain, mock.MagicMock())

  @mock.patch.object(client.SSL, 'Context', autospec=True)
  @mock.patch.object(client.SSL, 'Connection', autospec=True)
  def testConnect(self, connection_mock, context_mock):
    """Test connect()."""
    context = context_mock()
    conn = connection_mock(context)

    connection_mock.reset_mock()
    context_mock.reset_mock()

    self.mbc._ca_cert_chain = 'cert chain foo'

    context_mock.return_value = context
    connection_mock.return_value = conn

    with mock.patch.object(self.mbc, '_LoadCACertChain') as load_ca_chain_mock:
      self.mbc.connect()
      self.assertEqual(self.mbc.sock, conn)

      load_ca_chain_mock.assert_called_once_with(context)

    context_mock.assert_called_once_with(client._SSL_VERSION)
    connection_mock.assert_called_once_with(context)

    conn.connect.assert_called_once_with((self.mbc.host, self.mbc.port))
    if client._CIPHER_LIST:
      context.assert_has_calls([mock.call.set_cipher_list(client._CIPHER_LIST)])

  def testConnectWhenNoCACertChain(self):
    """Test connect()."""
    context = mock.create_autospec(M2Crypto.SSL.Context)

    with mock.patch.object(client.SSL, 'Context', return_value=context):
      self.assertRaises(client.SimianClientError, self.mbc.connect)

      if client._CIPHER_LIST:
        context.assert_has_calls(
            [mock.call.set_cipher_list(client._CIPHER_LIST)])


class HttpsClientTest(basetest.TestCase):
  """Test HttpsClient class."""

  def setUp(self):
    super(HttpsClientTest, self).setUp()
    self.stubs = stubout.StubOutForTesting()
    self.hostname = 'hostname'
    self.port = None
    self.client = client.HttpsClient(self.hostname)

  def tearDown(self):
    super(HttpsClientTest, self).tearDown()
    self.stubs.UnsetAll()

  @mock.patch.object(client.HttpsClient, '_LoadHost')
  def testInit(self, mock_lh):
    """Test __init__()."""
    i = client.HttpsClient(self.hostname)
    self.assertEqual(i._progress_callback, None)
    self.assertEqual(i._ca_cert_chain, None)

    mock_lh.assert_called_once_with(self.hostname, None, None)

  def testLoadHost(self):
    """Test _LoadHost()."""
    self.client._LoadHost('host')
    self.assertEqual(self.client.hostname, 'host')
    self.assertEqual(self.client.port, None)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('host', 12345)
    self.assertEqual(self.client.hostname, 'host')
    self.assertEqual(self.client.port, 12345)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('https://tsoh:54321')
    self.assertEqual(self.client.hostname, 'tsoh')
    self.assertEqual(self.client.port, 54321)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('https://tsoh:54321', 9999)
    self.assertEqual(self.client.hostname, 'tsoh')
    self.assertEqual(self.client.port, 54321)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('foo.bar:5555')
    self.assertEqual(self.client.hostname, 'foo.bar')
    self.assertEqual(self.client.port, 5555)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('http://nonsecurehost')
    self.assertEqual(self.client.hostname, 'nonsecurehost')
    self.assertEqual(self.client.port, None)
    self.assertFalse(self.client.use_https)

    self.client._LoadHost('https://dev1.latest.%s' % client.SERVER_HOSTNAME)
    self.assertEqual(
        self.client.hostname, 'dev1.latest.%s' % client.SERVER_HOSTNAME)
    self.assertEqual(self.client.port, None)
    self.assertTrue(self.client.use_https)

    self.client._LoadHost('http://dev2.latest.%s' % client.SERVER_HOSTNAME)
    self.assertEqual(
        self.client.hostname, 'dev2.latest.%s' % client.SERVER_HOSTNAME)
    self.assertEqual(self.client.port, None)
    self.assertFalse(self.client.use_https)

    self.client._LoadHost('http://nonsecurehost:1234')
    self.assertEqual(self.client.hostname, 'nonsecurehost')
    self.assertEqual(self.client.port, 1234)
    self.assertFalse(self.client.use_https)

    self.client._LoadHost(u'http://unicodehost')
    self.assertTrue(type(self.client.hostname) is str)
    self.assertEqual(self.client.hostname, 'unicodehost')

    self.client._LoadHost(u'http://unicodehost', proxy=u'http://evilproxy:9')
    self.assertTrue(type(self.client.hostname) is str)
    self.assertEqual(self.client.hostname, 'unicodehost')
    self.assertTrue(type(self.client.proxy_hostname) is str)
    self.assertEqual(self.client.proxy_hostname, 'evilproxy')
    self.assertEqual(self.client.proxy_port, 9)
    self.assertFalse(self.client.proxy_use_https)

    self.client._LoadHost(u'http://unicodehost', proxy=u'https://evilprxssl:8')
    self.assertTrue(type(self.client.hostname) is str)
    self.assertEqual(self.client.hostname, 'unicodehost')
    self.assertTrue(type(self.client.proxy_hostname) is str)
    self.assertEqual(self.client.proxy_hostname, 'evilprxssl')
    self.assertEqual(self.client.proxy_port, 8)
    self.assertTrue(self.client.proxy_use_https)

  def testSetCACertChain(self):
    """Test SetCACertChain()."""
    self.client.SetCACertChain('foo')
    self.assertEqual(self.client._ca_cert_chain, 'foo')

  def _TestConnect(self, test_client, hostname, port):
    """Test _Connect()."""
    m = mock.Mock()
    m.return_value = m

    test_client._ca_cert_chain = 'cert chain'
    use_https = (
        (not test_client.proxy_hostname and test_client.use_https) or
        (test_client.proxy_hostname and test_client.proxy_use_https))
    if use_https:
      self.stubs.Set(client, 'HTTPSMultiBodyConnection', m)
    else:
      self.stubs.Set(client, 'HTTPMultiBodyConnection', m)

    expected = [mock.call(hostname, port)]
    if use_https:
      expected.append(mock.call.SetCACertChain('cert chain'))
    expected.append(mock.call.connect())

    test_client._Connect()

    m.assert_has_calls(expected)

  def testConnect(self):
    self._TestConnect(self.client, self.hostname, self.port)

  def testConnectWithProxy(self):
    test_client = client.HttpsClient(self.hostname, proxy='proxyhost:123')
    self._TestConnect(test_client, 'proxyhost', 123)

  def testGetResponseNoFile(self):
    """Test _GetResponse() storing body directly into response obj."""
    headers = {'foo': 1}
    status = 200
    body = 'howdy sir'
    body_len = len(body)

    response = mock.create_autospec(httplib.HTTPResponse)
    response.getheaders.return_value = headers
    response.read.side_effect = [body, None]
    response.status = status
    response.reason = 'OK'

    conn = mock.create_autospec(httplib.HTTPConnection)
    conn.getresponse.return_value = response

    r = self.client._GetResponse(conn)
    self.assertEqual(r.headers, headers)
    self.assertEqual(r.status, status)
    self.assertEqual(r.body, body)
    self.assertEqual(r.body_len, body_len)

  def testGetResponseOutputFile(self):
    """Test _GetResponse() sending the body to output_file."""
    headers = {'foo': 1}
    status = 200
    body = 'howdy sir'
    body_len = len(body)
    path = '/file'

    fs = fake_filesystem.FakeFilesystem()
    fs.CreateFile(path)
    fake_open = fake_filesystem.FakeFileOpen(fs)
    output_file = fake_open(path, 'w')

    response = mock.create_autospec(httplib.HTTPResponse)
    response.getheaders.return_value = headers
    response.read.side_effect = [body, None]
    response.status = status
    response.reason = 'Ok'

    conn = mock.create_autospec(httplib.HTTPSConnection)
    conn.getresponse.return_value = response

    r = self.client._GetResponse(conn, output_file=output_file)
    self.assertEqual(r.headers, headers)
    self.assertEqual(r.status, status)
    self.assertEqual(r.body, None)
    self.assertEqual(r.body_len, body_len)

    output_file.close()
    self.assertEqual(body, fake_open(path).read())

  def testRequest(self):
    """Test _Request()."""
    method = 'zGET'
    url = u'/url'
    body1 = {'encodeme': 1}
    body1_encoded = client.urllib.urlencode(body1)
    body2 = 'leave this alone'
    headers = {'User-Agent': 'gzip'}

    conn = mock.create_autospec(httplib.HTTPConnection)

    self.client._Request(method, conn, url, body1, headers)
    self.client._Request(method, conn, url, body2, headers)

    conn.request.assert_has_calls([
        mock.call(method, str(url), body=body1_encoded, headers=headers),
        mock.call(method, str(url), body=body2, headers=headers)])

  def _TestDoRequestResponse(self, test_client, url, req_url):
    """Test _DoRequestResponse()."""
    method = 'zomg'
    conn = mock.create_autospec(httplib.HTTPConnection)
    body = 'body'
    headers = 'headers'
    output_file = None
    response = mock.create_autospec(httplib.HTTPResponse)
    response.status = 200
    proxy_use_https = test_client.proxy_use_https

    with mock.patch.object(test_client, '_Connect', return_value=conn):
      request_mock = mock.create_autospec(test_client._Request)
      self.stubs.Set(test_client, '_Request', request_mock)
      get_response_mock = mock.Mock(return_value=response)
      self.stubs.Set(test_client, '_GetResponse', get_response_mock)

      self.assertEqual(
          response,
          test_client._DoRequestResponse(
              method, url, body, headers, output_file))
      request_mock.assert_called_once_with(
          method, conn, req_url, body=body, headers=headers)
      get_response_mock.assert_called_once_with(conn, output_file=output_file)

    conn.assert_not_called()
    response.assert_not_called()

    with mock.patch.object(
        test_client, '_Connect', side_effect=client.httplib.HTTPException):
      self.assertRaises(
          client.HTTPError,
          test_client._DoRequestResponse,
          method, url, body, headers, output_file)

  def testDoRequestResponse(self):
    self._TestDoRequestResponse(self.client, '/url', '/url')

  def testDoHttpRequestResponseWithHttpProxy(self):
    """Test a https request via a http proxy."""
    test_client = client.HttpsClient(
        'http://%s' % self.hostname, proxy='proxyhost:123')
    req_url = 'http://' + self.hostname + '/url'
    self._TestDoRequestResponse(test_client, '/url', req_url)

  def testDoHttpsRequestResponseWithHttpProxy(self):
    """Test a https request via a http proxy."""
    # default is https
    test_client = client.HttpsClient(
        self.hostname, proxy='http://proxyhost:124')
    req_url = 'https://' + self.hostname + '/url'
    self._TestDoRequestResponse(test_client, '/url', req_url)

  def testDoHttpRequestResponseWithHttpsProxy(self):
    """Test a https request via a http proxy."""
    test_client = client.HttpsClient(
        'http://%s' % self.hostname, proxy='https://proxyhost:125')
    req_url = 'http://' + self.hostname + '/url'
    self._TestDoRequestResponse(test_client, '/url', req_url)

  def testDoHttpsRequestResponseWithHttpsProxy(self):
    """Test a https request via a http proxy."""
    # default is https
    test_client = client.HttpsClient(
        self.hostname, proxy='https://proxyhost:126')
    req_url = 'https://' + self.hostname + '/url'
    self._TestDoRequestResponse(test_client, '/url', req_url)

  def testDoWithInvalidMethod(self):
    """Test Do() with invalid method."""
    self.assertRaises(
        NotImplementedError,
        self.client.Do, 'badmethod', '/url')

  @mock.patch.object(client.time, 'sleep')
  def testDo(self, mock_sleep):
    """Test Do() with correct arguments and no output_filename."""
    method = 'GET'
    url = 'url'
    body = None
    headers = None
    output_file = None
    output_filename = None

    # HTTP 500 should retry.
    mock_response_fail = mock.create_autospec(httplib.HTTPResponse)
    mock_response_fail.status = 500
    # HTTP 200 should succeed.
    mock_response = mock.create_autospec(httplib.HTTPResponse)
    mock_response.status = 200

    with mock.patch.object(
        self.client,
        '_DoRequestResponse',
        side_effect=[
            mock_response_fail, mock_response]) as mock_do_request_response:

      inorder_calls = mock.Mock()
      inorder_calls.attach_mock(mock_sleep, 'sleep')
      inorder_calls.attach_mock(mock_do_request_response, '_DoRequestResponse')
      do_request_response_call = mock.call._DoRequestResponse(
          method, url, body=body, headers={}, output_file=output_file)

      self.client.Do(method, url, body, headers, output_filename)

      inorder_calls.assert_has_calls([
          mock.call.sleep(0), do_request_response_call,
          mock.call.sleep(5), do_request_response_call])

  @mock.patch.object(client.time, 'sleep')
  def testDoWithRetryHttp500(self, mock_sleep):
    """Test Do() with a HTTP 500, thus a retry."""
    method = 'GET'
    url = 'url'
    body = None
    headers = None
    output_file = None
    output_filename = None

    inorder_calls = mock.Mock()
    inorder_calls.attach_mock(mock_sleep, 'sleep')

    mock_response = mock.create_autospec(httplib.HTTPResponse)
    mock_response.status = 500
    with mock.patch.object(
        self.client,
        '_DoRequestResponse',
        return_value=mock_response) as mock_do_request_response:
      inorder_calls.attach_mock(mock_do_request_response, '_DoRequestResponse')

      self.client.Do(method, url, body, headers, output_filename)

    expected = []
    for i in xrange(0, client.DEFAULT_HTTP_ATTEMPTS):
      expected += [
          mock.call.sleep(i * 5),
          mock.call._DoRequestResponse(
              method, url, body=body, headers={},
              output_file=output_file)]
    inorder_calls.assert_has_calls(expected)

  @mock.patch.object(client.time, 'sleep')
  def testDoWithRetryHttpError(self, mock_sleep):
    """Test Do() with a HTTP 500, thus a retry, but ending with HTTPError."""
    method = 'GET'
    url = 'url'
    body = None
    headers = None
    output_file = None
    output_filename = None

    inorder_calls = mock.Mock()
    inorder_calls.attach_mock(mock_sleep, 'sleep')

    mock_response = mock.create_autospec(httplib.HTTPResponse)
    mock_response.status = 500
    with mock.patch.object(
        self.client,
        '_DoRequestResponse',
        side_effect=client.HTTPError) as mock_do_request_response:
      inorder_calls.attach_mock(mock_do_request_response, '_DoRequestResponse')

      self.assertRaises(
          client.HTTPError,
          self.client.Do,
          method, url, body, headers, output_filename)

    expected = []
    for i in xrange(0, client.DEFAULT_HTTP_ATTEMPTS):
      expected += [
          mock.call.sleep(i * 5),
          mock.call._DoRequestResponse(
              method, url, body=body, headers={},
              output_file=output_file)]
    inorder_calls.assert_has_calls(expected)

  def testDoWithOutputFilename(self):
    """Test Do() where an output_filename is supplied."""
    method = 'GET'
    url = 'url'
    body = None
    headers = {}

    output_file = mock.create_autospec(file)
    mock_open = mock.Mock(return_value=output_file)
    output_filename = '/tmpfile'

    mock_response = mock.create_autospec(httplib.HTTPResponse)
    mock_response.status = 200

    with mock.patch.object(
        self.client,
        '_DoRequestResponse',
        return_value=mock_response) as mock_do_request_response:
      self.client.Do(
          method, url, body, headers, output_filename, _open=mock_open)

      mock_do_request_response.assert_called_once_with(
          method, url, body=body, headers={}, output_file=output_file)

  def testDoWithProxy(self):
    """Test Do() with a proxy specified."""
    method = 'GET'
    url = 'url'
    proxy = 'proxyhost:123'

    # Working case.
    mock_response = mock.create_autospec(httplib.HTTPConnection)
    mock_response.status = 200
    test_client = client.HttpsClient(self.hostname, proxy=proxy)

    with mock.patch.object(
        test_client,
        '_DoRequestResponse',
        return_value=mock_response) as mock_do_request_response:
      test_client.Do(method, url)
      mock_do_request_response.assert_called_once_with(
          method, url, body=None, headers={}, output_file=None)

    # No port case.
    proxy = 'proxyhost'
    self.assertRaises(
        client.Error,
        client.HttpsClient, self.hostname, proxy=proxy)
    # Bad port case.
    proxy = 'proxyhost:alpha'
    self.assertRaises(
        client.Error,
        client.HttpsClient, self.hostname, proxy=proxy)


class HttpsAuthClientTest(basetest.TestCase):
  """Test HttpsAuthClient."""

  def setUp(self):
    super(HttpsAuthClientTest, self).setUp()
    self.stubs = stubout.StubOutForTesting()
    self.hostname = 'hostname'
    self.port = None
    self.client = client.HttpsAuthClient(self.hostname)

    self.fs = fake_filesystem.FakeFilesystem()
    fake_os = fake_filesystem.FakeOsModule(self.fs)
    self.fake_open = fake_filesystem.FakeFileOpen(self.fs)
    self.stubs.Set(client, 'os', fake_os)

  def tearDown(self):
    super(HttpsAuthClientTest, self).tearDown()
    self.stubs.UnsetAll()

  @mock.patch.object(client.HttpsAuthClient, '_LoadRootCertChain')
  def testInit(self, _):
    """Test __init__()."""
    c = client.HttpsAuthClient(self.hostname)
    self.assertEqual(c._auth1, None)
    self.assertEqual(c._cookie_token, None)


  def testPlatformSetup(self):
    """Test PlatformSetup()."""
    with mock.patch.object(client.platform, 'system', return_value='Darwin'):
      self.client.facter_cache_path = 'x'
      self.client._PlatformSetup()
      self.assertEqual(
          self.client.facter_cache_path, self.client.FACTER_CACHE_OSX_PATH)

    with mock.patch.object(client.platform, 'system', return_value='other'):
      self.client.facter_cache_path = 'x'
      self.client._PlatformSetup()
      self.assertEqual(
          self.client.facter_cache_path, self.client.FACTER_CACHE_DEFAULT_PATH)

  def testGetFacter(self):
    """Test GetFacter()."""
    st_dt = client.datetime.datetime.now()
    facter = {'foo': 'bar', 'one': '1'}
    file_path = '/x'
    lines = [
        'foo => bar',
        'one => 1',
        'I_am_invalid',
    ]

    fake_file = self.fs.CreateFile(file_path, contents='\n'.join(lines))
    fake_file.st_uid = 0
    fake_file.st_mtime = int(st_dt.strftime('%s'))

    self.client.facter_cache_path = file_path

    with mock.patch.object(client.os, 'geteuid', return_value=0):
      self.assertEqual(facter, self.client.GetFacter(open_fn=self.fake_open))

  def testGetFacterWhenInsecureFileForRoot(self):
    """Test GetFacter()."""
    file_path = '/x'

    self.client.facter_cache_path = file_path

    fake_file = self.fs.CreateFile(file_path)
    fake_file.st_uid = 100

    # root
    with mock.patch.object(client.os, 'geteuid', return_value=0):
      fake_open = mock.Mock()
      self.assertEqual({}, self.client.GetFacter(open_fn=fake_open))
      fake_open.assert_not_called()

    # same regular user
    with mock.patch.object(client.os, 'geteuid', return_value=200):
      fake_open = mock.Mock()
      self.assertEqual({}, self.client.GetFacter(open_fn=fake_open))
      fake_open.assert_not_called()

  @mock.patch.object(client.os.path, 'isfile', return_value=False)
  def testGetFacterWhenCacheDoesNotExist(self, _):
    """Test GetFacter() with a nonexistent cache file."""
    self.client.facter_cache_path = '/x'

    self.assertEqual({}, self.client.GetFacter())

  def testGetFacterWhenCachePathIsNone(self):
    """Test GetFacter() with facter_cache_path is None."""
    self.client.facter_cache_path = None

    self.assertEqual({}, self.client.GetFacter())

  def testGetAuthTokenFromHeadersSuccess(self):
    token = '%s=123; secure; httponly;' % auth.AUTH_TOKEN_COOKIE
    result = self.client._GetAuthTokenFromHeaders(
        {'set-cookie': 'other=value;,%s,something=else;' % token})
    self.assertEqual(token, result)

  def testGetAuthTokenFromHeadersMissingHeader(self):
    self.assertRaises(
        client.SimianClientError,
        self.client._GetAuthTokenFromHeaders,
        {'set-cookie': ''})


class SimianClientTest(basetest.TestCase):
  """Test SimianClient class."""

  def setUp(self):
    self.hostname = 'hostname'
    self.port = None
    self.client = client.SimianClient(self.hostname)

  def testInitWithoutHostname(self):
    """Test __init__() without a hostname passed."""
    user = 'foouser'

    with mock.patch.object(
        client.SimianClient, '_GetLoggedOnUser', return_value=user):
      clienttmp = client.SimianClient()
      self.assertEqual(clienttmp.hostname, client.SERVER_HOSTNAME)
      self.assertEqual(clienttmp._user, user)

  def testInitWithHostname(self):
    """Test __init__() with a hostname passed."""
    user = 'foouser'
    with mock.patch.object(
        client.SimianClient, '_GetLoggedOnUser', return_value=user):
      clienttmp = client.SimianClient('foo')
      self.assertEqual(clienttmp.hostname, 'foo')
      self.assertEqual(clienttmp._user, user)

  def testInitAsRoot(self):
    """Test __init__() with a hostname passed."""
    with mock.patch.object(
        client.SimianClient, '_GetLoggedOnUser', return_value='root'):
      self.assertRaises(client.SimianClientError, client.SimianClient)

  def testIsDefaultHostClient(self):
    """Test IsDefaultHostClient()."""
    self.client._default_hostname = 'foo'
    self.assertEqual(self.client.IsDefaultHostClient(), 'foo')

  def testSimianRequest(self):
    """Test _SimianRequest()."""
    method = 'zGET'
    url = '/url'
    headers = {'foo': 'bar'}
    output_filename = None

    good_response = client.Response(status=200, body='hello there')

    with mock.patch.object(
        self.client, 'Do', return_value=good_response) as do_mock:
      self.assertEqual(
          good_response.body,
          self.client._SimianRequest(method, url, headers=headers))

      do_mock.assert_called_once_with(
          method, url, body=None, headers=headers,
          output_filename=output_filename)

  def testSimianRequestWithError(self):
    """Test _SimianRequest() with an error status returned."""
    method = 'zGET'
    url = '/url'
    headers = {'foo': 'bar'}
    output_filename = None

    error_response = client.Response(status=401, body='fooerror')

    with mock.patch.object(
        self.client, 'Do', return_value=error_response) as do_mock:
      self.assertRaises(
          client.SimianServerError,
          self.client._SimianRequest, method, url, headers=headers)

      do_mock.assert_called_once_with(
          method, url, body=None, headers=headers,
          output_filename=output_filename)

  def GenericStubTestAndReturn(
      self,
      method,
      method_return,
      method_args,
      stub_method_name, stub_method_return, *stub_args, **stub_kwargs):
    """Helper test method.

    Args:
      method: method, to invoke in the test
      method_return: any, value to expect from method
      method_args: list, arguments to send to method during test
      stub_method_name: str, method name to stub out in SimianClient class
      stub_method_return: any, value to return from stubbed method call
      stub_args: list, args to expect when calling stub_method_name
      stub_kwargs: dict, kwargs to expect when calling stub_method_name
    """
    with mock.patch.object(
        self.client,
        stub_method_name,
        return_value=stub_method_return) as m:
      got_rv = method(*method_args)
      self.assertEqual(got_rv, method_return)
      m.assert_called_once_with(*stub_args, **stub_kwargs)

  def GenericStubTest(
      self,
      method, method_args,
      stub_method_name, *stub_args, **stub_kwargs):
    """Helper test method.

    Args:
      method: method, to invoke in the test
      method_args: list, arguments to send to method during test
      stub_method_name: str, method name to stub out in SimianClient class
      stub_args: list, args to expect when calling stub_method_name
      stub_kwargs: dict, kwargs to expect when calling stub_method_name
    Returns:
      string, 'returnval'
    """
    rv = 'returnval'
    return self.GenericStubTestAndReturn(
        method, rv, method_args,
        stub_method_name, rv, *stub_args, **stub_kwargs)

  def testGetCatalog(self):
    """Test GetCatalog()."""
    name = 'name'
    self.GenericStubTest(
        self.client.GetCatalog, [name],
        '_SimianRequest', 'GET', '/catalog/%s' % name)

  def testGetManifest(self):
    """Test GetManifest()."""
    name = 'name'
    self.GenericStubTest(
        self.client.GetManifest, [name],
        '_SimianRequest', 'GET', '/manifest/%s' % name)

  def testGetPackage(self):
    """Test GetPackage()."""
    name = 'name'
    self.GenericStubTest(
        self.client.GetPackage, [name],
        '_SimianRequest', 'GET', '/pkgs/%s' % name, output_filename=None)

  def testGetPackageInfo(self):
    """Test GetPackageInfo()."""
    filename = 'name.dmg'
    response = mock.create_autospec(httplib.HTTPResponse)
    response.body = 'hello'
    self.GenericStubTestAndReturn(
        self.client.GetPackageInfo,
        'hello',
        [filename],
        '_SimianRequest',
        response,
        'GET', '/pkgsinfo/%s' % filename, full_response=True)

  def testGetPackageInfoWhenHash(self):
    """Test GetPackageInfo()."""
    filename = 'name.dmg'
    response = mock.create_autospec(httplib.HTTPResponse)
    response.body = 'body'
    response.headers = {'x-pkgsinfo-hash': 'hash'}
    self.GenericStubTestAndReturn(
        self.client.GetPackageInfo, ('hash', 'body'),
        [filename, True],
        '_SimianRequest',
        response,
        'GET', '/pkgsinfo/%s?hash=1' % filename, full_response=True)

  def testDownloadPackage(self):
    """Test DownloadPackage()."""
    filename = 'foo'

    self.GenericStubTest(
        self.client.DownloadPackage,
        [filename],
        '_SimianRequest', 'GET',
        '/pkgs/%s' % filename, output_filename=filename)

  def testPostReport(self):
    """Test PostReport()."""
    report_type = 'foo'
    params = {'bar': 1}
    url = '/reports'
    body = '_report_type=%s&%s' % (
        report_type,
        client.urllib.urlencode(params, doseq=True))

    self.GenericStubTest(
        self.client.PostReport, [report_type, params],
        '_SimianRequest', 'POST', url, body)

  def testPostReportWhenFeedback(self):
    """Test PostReport()."""
    report_type = 'foo'
    params = {'bar': 1}
    url = '/reports'
    body = '_report_type=%s&%s&_feedback=1' % (
        report_type,
        client.urllib.urlencode(params, doseq=True))

    self.GenericStubTest(
        self.client.PostReport, [report_type, params, True],
        '_SimianRequest', 'POST', url, body)

  def testPostReportBody(self):
    """Test PostReportBody()."""
    url = '/reports'
    body = 'foo'

    self.GenericStubTest(
        self.client.PostReportBody, [body],
        '_SimianRequest', 'POST', url, body)

  def testPostReportBodyWhenFeedback(self):
    """Test PostReportBody()."""
    url = '/reports'
    body = 'foo'
    body_with_feedback = 'foo&_feedback=1'

    self.GenericStubTest(
        self.client.PostReportBody, [body, True],
        '_SimianRequest', 'POST', url, body_with_feedback)

  @mock.patch.object(client.os.path, 'isfile', return_value=True)
  def testUploadFile(self, _):
    """Test UploadFile()."""
    file_type = 'log'
    file_name = 'file.log'
    file_path = 'path/to/' + file_name
    url = '/uploadfile/%s/%s' % (file_type, file_name)

    mock_file = mock.create_autospec(file)
    mock_open = mock.Mock(return_value=mock_file)

    with mock.patch.object(self.client, 'Do') as mock_do:
      self.client.UploadFile(file_path, file_type, _open=mock_open)
      mock_do.assert_called_once_with('PUT', url, mock_file)

  @mock.patch.object(client.logging, 'error', autospec=True)
  @mock.patch.object(client.os.path, 'isfile', return_value=False)
  def testUploadFileWhenLogNotFound(self, mock_isfile, mock_logging_error):
    """Test UploadFile() when the file is not found."""
    file_path = 'path/to/file.log'

    self.client.UploadFile(file_path, 'foo-file-type')

    mock_logging_error.assert_called_once_with(
        'UploadFile file not found: %s', file_path)
    mock_isfile.assert_called_once_with(file_path)


class SimianAuthClientTest(basetest.TestCase):
  """Test SimianAuthClient class."""

  def setUp(self):
    super(SimianAuthClientTest, self).setUp()
    self.pac = client.SimianAuthClient()

  def testGetAuthToken(self):
    """Test GetAuthToken()."""
    with mock.patch.object(self.pac, 'DoSimianAuth'):
      self.pac._cookie_token = 'token'

      self.assertEqual(self.pac.GetAuthToken(), 'token')

  def testLogoutAuthToken(self):
    """Test LogoutAuthToken()."""
    url = '/auth?logout=True'

    with mock.patch.object(self.pac, '_SimianRequest', return_value='ok'):
      self.assertTrue(self.pac.LogoutAuthToken())

      self.pac._SimianRequest.assert_called_once_with('GET', url)

  def testLogoutAuthTokenWhenFail(self):
    """Test LogoutAuthToken()."""
    url = '/auth?logout=True'

    with mock.patch.object(
        self.pac, '_SimianRequest', side_effect=client.SimianServerError):
      self.assertFalse(self.pac.LogoutAuthToken())
      self.pac._SimianRequest.assert_called_once_with('GET', url)


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  basetest.main()


if __name__ == '__main__':
  app.run()
