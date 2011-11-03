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

from simian import settings

# Public certificate for CA of server and client certificates
CA_PUBLIC_CERT_PEM = settings.CA_PUBLIC_CERT_PEM

# Public certificate, signed by CA, for server
SERVER_PUBLIC_CERT_PEM = settings.SERVER_PUBLIC_CERT_PEM


# Root CA cert chain used by the client to verify the server SSL cert.
ROOT_CA_CERT_CHAIN_PEM = getattr(settings, 'ROOT_CA_CERT_CHAIN_PEM', None)


# Only accept client certificates issued by this DN (i.e. CN=ca.example.com)
REQUIRED_ISSUER = settings.REQUIRED_ISSUER


# Path to the directory of client certificates (public cert and private key).
CLIENT_SSL_PATH = getattr(settings, 'CLIENT_SSL_PATH', None)


# Name of the cookie set by server
AUTH_TOKEN_COOKIE = 'Auth1Token'

##
## Important configurable items regarding SSL connections
##

# SERVER_CERT_VALID_SUBJECTS
#
# The following list of subjects is validated against each cert subject in
# the chain during a Simian client SSL connection startup and certificate
# validation.
#
# If any connection cert subject does not match one of the following, an
# error WILL be raised.
#
# If any subject listed below is not present in any of the connection cert
# subjects, an error WILL NOT be raised.  This is a matching list, not a
# requirement list.
#
# However, if NO cert subject listed below is matched during the connection,
# an error WILL be raised.

if settings.DOMAIN == 'appspot.com':
  CERT_DOMAIN = '*.appspot.com'
else:
  CERT_DOMAIN = 'sandbox.google.com'

SERVER_CERT_VALID_SUBJECTS = [
    '/C=US/O=Equifax/OU=Equifax Secure Certificate Authority',
    '/C=US/O=Google Inc/CN=Google Internet Authority',
    '/C=US/ST=California/L=Mountain View/O=Google Inc/CN=%s' % CERT_DOMAIN,
]

# SERVER_CERT_REQUIRE_SUBJECTS
#
# The following list of subjects is validated against the list of all
# matched cert subjects after the SSL connection has started.  Each of the
# following subjects must also appear in SERVER_CERT_VALID_SUBJECTS for them
# to have been initially matched.
#
# If one of the following subjects was not matched, an error WILL be raised
# which will take down the connection.

SERVER_CERT_REQUIRE_SUBJECTS = [
    '/C=US/O=Google Inc/CN=Google Internet Authority',
    '/C=US/ST=California/L=Mountain View/O=Google Inc/CN=%s' % CERT_DOMAIN,
]