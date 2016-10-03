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

from google.apputils import app
from google.apputils import basetest

from simian.mac.admin import release_report


class ReleaseReportModelTest(basetest.TestCase):
  """Test the release_report module."""

  def testGetOSXMajorVersion(self):
    self.assertEqual('5', release_report.GetOSXMajorVersion('10.5'))
    self.assertEqual('10', release_report.GetOSXMajorVersion('10.10'))
    self.assertEqual('11', release_report.GetOSXMajorVersion('10.11'))
    self.assertEqual('11', release_report.GetOSXMajorVersion('10.11.1'))
    self.assertEqual('9', release_report.GetOSXMajorVersion('10.9.10'))
    self.assertEqual(None, release_report.GetOSXMajorVersion('10'))
    self.assertEqual(None, release_report.GetOSXMajorVersion(None))


def main(_):
  basetest.main()


if __name__ == '__main__':
  app.run()
