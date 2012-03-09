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

"""deletepkg module tests."""



import logging
logging.basicConfig(filename='/dev/null')

from google.apputils import app
from simian.mac.munki.handlers import deletepkg
from simian.mac.common import test


class DeletePackageTest(test.RequestHandlerTest):

  def GetTestClassInstance(self):
    return deletepkg.DeletePackage()

  def GetTestClassModule(self):
    return deletepkg

  def testDeleteSuccess(self):
    """Test delete() with valid input params, giving success."""
    filename = 'pkgname.dmg'
    blobstore_key = '123'
    catalogs = ['catalog1', 'catalog2']
    install_types = ['managed_installs']
    pkginfo_str = 'pkginfo'
    user = 'foouser'

    self.mox.StubOutWithMock(deletepkg.gae_util, 'SafeBlobDel')
    self.mox.StubOutWithMock(deletepkg.models.Catalog, 'Generate')
    mock_pkginfo = self.mox.CreateMockAnything()
    mock_pkginfo.blobstore_key = blobstore_key
    mock_pkginfo.catalogs = catalogs
    mock_pkginfo.install_types = install_types
    mock_pkginfo.plist = pkginfo_str
    session = self.mox.CreateMockAnything()
    session.uuid = user
    self.MockDoMunkiAuth(
        require_level=deletepkg.gaeserver.LEVEL_UPLOADPKG, and_return=session)
    self.request.get('filename').AndReturn(filename)
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(mock_pkginfo)
    mock_pkginfo.delete().AndReturn(None)
    deletepkg.gae_util.SafeBlobDel(blobstore_key).AndReturn(None)
    for catalog in catalogs:
      deletepkg.models.Catalog.Generate(catalog).AndReturn(None)

    mock_log = self.MockModel(
        'AdminPackageLog', user=user, action='deletepkg', filename=filename,
        catalogs=catalogs, install_types=install_types, plist=pkginfo_str)
    mock_log.put().AndReturn(None)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()

  def testDeleteNameNotFound(self):
    """Test delete() where the filename is not found."""
    filename = 'pkgname.dmg'
    self.MockDoMunkiAuth(require_level=deletepkg.gaeserver.LEVEL_UPLOADPKG)
    self.request.get('filename').AndReturn(filename)
    self.MockModelStaticBase(
        'PackageInfo', 'get_by_key_name', filename).AndReturn(None)
    self.response.set_status(404)
    self.response.out.write('Pkginfo does not exist: %s' % filename)

    self.mox.ReplayAll()
    self.c.post()
    self.mox.VerifyAll()


def main(unused_argv):
  test.main(unused_argv)


if __name__ == '__main__':
  app.run()