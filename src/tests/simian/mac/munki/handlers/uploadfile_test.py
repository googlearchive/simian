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
"""Munki uploadfile module tests."""

import logging

from google.apputils import app
from tests.simian.mac.common import test
from simian.mac.munki.handlers import uploadfile


class UploadFileHandlerTest(test.RequestHandlerTest):
  """uploadfile.UploadFile handlers tests."""

  def GetTestClassInstance(self):
    return uploadfile.UploadFile()

  def GetTestClassModule(self):
    return uploadfile

  def testPut(self):
    """Tests UploadFile.put()."""
    self.mox.StubOutWithMock(uploadfile.main_common, 'SanitizeUUID')
    self.mox.StubOutWithMock(uploadfile.models, 'ClientLogFile')
    self.mox.StubOutWithMock(uploadfile.models.Computer, 'get_by_key_name')
    self.mox.StubOutWithMock(uploadfile.deferred, 'defer')

    uuid = 'foouuid'
    file_type = 'log'
    file_name = 'file.log'
    file_body = 'asdfasdf'
    key_name = '%s_%s' % (uuid, file_name)
    self.request.body = file_body
    notify_addresses_str = 'foo@example.com,bar@example.com'
    notify_addresses_list = ['foo@example.com', 'bar@example.com']

    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoMunkiAuth(and_return=mock_session)
    uploadfile.main_common.SanitizeUUID(uuid).AndReturn(uuid)

    mock_model = self.mox.CreateMockAnything()
    uploadfile.models.ClientLogFile(key_name=key_name).AndReturn(mock_model)
    mock_model.put().AndReturn(None)

    mock_computer = self.mox.CreateMockAnything()
    mock_computer.upload_logs_and_notify = notify_addresses_str
    uploadfile.models.Computer.get_by_key_name(uuid).AndReturn(mock_computer)
    mock_computer.put().AndReturn(None)

    uploadfile.deferred.defer(
        uploadfile.SendNotificationEmail, notify_addresses_list, mock_computer,
        uploadfile.settings.SERVER_HOSTNAME)

    self.mox.ReplayAll()
    self.c.put(file_type=file_type, file_name=file_name)
    self.assertEqual(mock_model.log_file, file_body)
    self.assertEqual(mock_model.uuid, uuid)
    self.assertEqual(None, mock_computer.upload_logs_and_notify)
    self.mox.VerifyAll()

  def testPut404(self):
    """Tests UploadFile.put() with 404."""
    self.mox.StubOutWithMock(uploadfile.main_common, 'SanitizeUUID')

    uuid = 'foouuid'
    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoMunkiAuth(and_return=mock_session)
    uploadfile.main_common.SanitizeUUID(uuid).AndReturn(uuid)
    self.MockError(404)

    mock_session = self.mox.CreateMockAnything()
    mock_session.uuid = uuid
    self.MockDoMunkiAuth(and_return=mock_session)
    uploadfile.main_common.SanitizeUUID(uuid).AndReturn(uuid)
    self.MockError(404)

    self.mox.ReplayAll()
    self.c.put(file_type='log', file_name='')
    self.c.put(file_type='', file_name='fooname')
    self.mox.VerifyAll()


logging.basicConfig(filename='/dev/null')


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()
