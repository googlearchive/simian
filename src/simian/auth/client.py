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

"""Client module.  Contains classes to handle authentication and
authorization for Munki clients acting against Simian server.

Classes:

  AuthSessionSimianClient:  Session storage for Simian clients
  AuthSimianClient:         Simian client Auth class
"""




from simian.auth import base
from simian.auth import settings as auth_settings


class Error(Exception):
  """Base"""


class AuthSessionSimianClient(base.Auth1ClientSession):
  """AuthSession data container used for Simian Auth client."""


class AuthSimianClient(base.Auth1Client):
  """Auth1 client which uses AuthSessionSimianClient for session storage."""

  def __init__(self):
    super(AuthSimianClient, self).__init__()
    self._ca_pem = auth_settings.CA_PUBLIC_CERT_PEM
    self._server_cert_pem = auth_settings.SERVER_PUBLIC_CERT_PEM
    self._required_issuer = auth_settings.REQUIRED_ISSUER

  def GetSessionClass(self):
    return AuthSessionSimianClient