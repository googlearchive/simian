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

"""CLI code for Simian clients.

Contents:

  SimianCliClient:  base class for all CLI clients
"""




import datetime
import getopt
import logging
import os
import sys
from simian.client import client


class Error(Exception):
  """Base error."""


class CliError(Error):
  """Base error for any CLI error, this module and subclasses in
  other modules."""


class OptionError(CliError):
  """An error occured while parsing options."""


class EditorError(CliError):
  """Error occured while running text editor."""


class SimianCliClient(object):
  """Simian CLI client class.

  Generic functionality for all CLI clients goes here.  Don't put anything
  OS specific in this class.
  """

  # name of this tool
  NAME = 'simian'

  # suggested order: commands first, then command options
  LONGOPTS = [
      'help',
      'debug',
      'upload',
      'download',
      'delete',
      'edit',
      'server=',
      'user_auth=',
      'package=',
      'description=',
      'display_name=',
      'catalogs=',
      'manifests=',
      'install_types=',
      'edit_pkginfo',
      'unattended_install',
      'nounattended_install',
      'unattended_uninstall',
      'nounattended_uninstall',
      'list_packages',
  ]

  # no short options
  SHORTOPTS = ''

  # commands and their required options and handler method
  COMMANDS = {
      'upload': {
          'require': [ 'package', 'description', 'catalogs', 'install_types' ],
          'method': 'UploadPackage',
          'auth': 'userauth',
      },
      'download': {
          'require': [ 'package' ],
          'method': 'DownloadPackage',
          'auth': 'userauth',
      },
      'delete': {
          'require': [ 'package' ],
          'method': 'DeletePackage',
          'auth': 'userauth',
      },
      'edit': {
          'require': [ 'package' ],
          'method': 'EditPackageInfo',
          'auth': 'userauth',
      },
      'list_packages': {
          'require': [],
          'method': 'ListPackages',
          'auth': 'userauth',
      },
      'help': {
          'method': 'Usage',
      },
  }

  # usage text
  # TODO: make usage more easily updated from subclasses.

  ADDITIONAL_USAGE = ''
  USAGE = """
    Simian client

    usage: %s [command] [command options] ...

    commands:

    --upload
        upload a new (or update an existing) software package
    --download
        download a software package
    --delete
        delete a software package
    --edit
        edit an already uploaded software package
    --list_packages
        lists all packages of given --install_types and --catalogs.

    options:

    --package [filename or package name]
        for upload, specify the location.
        for deletion and edit, specify the name.
    --description [str description]
        for upload, specify description of the upload.
    --display_name [str display name]
        for upload, specify the human-readable display name of the upload.
    --edit_pkginfo
        when uploading or editing a package, run an editor on the generated
        package info before submitting it to the Simian server.
    --[no]unattended_install
        when uploading a package, add "unattended_install" bool to package info.
    --[no]unattended_uninstall
        when uploading a package, add "unattended_uninstall" bool to package
        info.
    --catalogs [unstable,testing,stable]
        specify the catalog names to target; comma delimited string
    --manifests [unstable,testing,stable]
        specify the manifest names to target; comma delimited string
    --install_types [managed_installs,managed_updates,type3]
        specify the install types of upload; comma delimited string
    --server [hostname(:port)]
        specify the Simian server location
%s
    --debug
        output debugging information

    --help
        this text
  """ % (NAME, ADDITIONAL_USAGE)

  def __init__(self):
    self.opts = []
    self.args = []
    self.config = {
      'debug': False,
      'server': None,
      'upload': None,
      'download': None,
      'delete': None,
      'edit': None,
      'package': None,
      'description': None,
      'display_name': None,
      'catalogs': None,
      'manifests': None,
      'install_types': None,
      'edit_pkginfo': None,
      'unattended_install': None,
      'unattended_uninstall': None,
      'list_packages': None,
    }
    self.command = None

  def GetSimianClientInstance(self, *args, **kwargs):
    """Returns an instance of the Simian client to use within this CLI.

    CLI subclasses should override this if necessary.
    """
    return client.SimianClient(*args, **kwargs)

  def Usage(self, msg=None):
    """Print usage information and optionally a message.

    Args:
      msg: str, optional
    """
    if msg is not None:
      print msg

    print self.USAGE

  def LoadArgs(self, args):
    """Load arguments as supplied from the CLI.

    Args:
      args: list, str arguments like '--option value'
    Raises:
      OptionError: if an error occurs in loading and parsing the options
    """
    try:
      opts, args = getopt.gnu_getopt(args, self.SHORTOPTS, self.LONGOPTS)
    except getopt.GetoptError, e:
      raise OptionError(e)

    self.opts = opts
    self.args = args
    self._LoadConfig()

  def _LoadConfig(self):
    """Given parsed options, load them into the config.

    Raises:
      OptionError: if inconsistent or missing options have been specified
    """
    # load specified options into the config
    for (optname, optval) in self.opts:
      if optname.startswith('--no') and optname[4:] in self.config:
        self.config[optname[4:]] = False
      else:
        self.config[optname[2:]] = optval

    # the help command is an exception -- look for it and run it immediately
    if 'help' in self.config:
      self.command = 'help'
      return

    # determine which command is intended to run
    found_cmd = []
    for cmd in self.COMMANDS:
      if cmd in self.config and self.config[cmd] is not None:
        found_cmd.append(cmd)

    if len(found_cmd) != 1:
      raise OptionError('Must specify a command, one of: %s' % ' '.join(
          map(lambda x: '--%s' % x, self.COMMANDS.keys())))

    # make sure all of the required command options were supplied
    # or default values satisfy them
    for req_cmdopt in self.COMMANDS[found_cmd[0]]['require']:
      if req_cmdopt not in self.config or self.config[req_cmdopt] is None:
        raise OptionError('Must specify command option --%s' % req_cmdopt)

    # everything is fine, set the discovered command
    self.command = found_cmd[0]

  def _PrintTransferProgress(self, bytes_sent, bytes_total):
    """Print transfer progress.

    Args:
      bytes_sent: int, bytes sent up to this call
      bytes_total: int, bytes to send, total, including bytes_sent
    """
    if bytes_total < 100000:  # ignore small transfers
      return

    if self._print_format is None:
      if os.isatty(sys.stdin.fileno()):
        self._print_format = 'tty'
      else:
        self._print_format = 'basic'

    if bytes_total == 0:
      percent_sent = 100.0
    else:
      percent_sent = (bytes_sent / (bytes_total * 1.0)) * 100

    if self._print_format == 'basic':
      if self._last_print_time is None:
        print 'Transfer progress:',
      if percent_sent % 5 == 0 and percent_sent > self._last_percent_sent:
        print '%f%% ...' % percent_sent,
      if percent_sent == 100:
        print
      self._last_print_time = 0

    elif self._print_format == 'tty':
      now = datetime.datetime.now()

      if (self._last_print_time is None or
          (now - self._last_print_time).seconds > 1 or
          percent_sent == 100 and self._last_percent_sent < 100):
        print 'Transfer progress: %6.2f%%\r' % percent_sent,
        sys.stdout.flush()
        self._last_print_time = now

      if percent_sent == 100 and self._last_percent_sent < 100:
        print

      sys.stdout.flush()

    self._last_percent_sent = percent_sent

  def _SetupProgressCallback(self):
    """Setup progress callback in client."""
    self._print_format = None
    self._last_print_time = None
    self._last_percent_sent = None
    self.client.SetProgressCallback(self._PrintTransferProgress)

  def _RunEditor(self, filename):
    """Run a text editor on filename.

    Args:
      filename: str, filename to edit
    Raises:
      EditorError: if the editor cannot be run or returns non-zero status
    """
    editor = None
    editors = (
        os.environ.get('EDITOR', None),
        os.environ.get('VISUAL', None),
        '/etc/alternatives/editor',
        '/usr/bin/vi')

    for p in editors:
      if p and os.path.exists(p):
        editor = p
        break

    if editor is None:
      raise EditorError('Cannot find editor for filename %s' % filename)

    argv = [editor]
    argv.append(filename)
    logging.debug('_RunEditor: spawning %s', ' '.join(argv))
    ec = os.spawnv(os.P_WAIT, argv[0], argv)
    if ec != 0:
      raise EditorError('Editor returned error exit status %d' % ec)

  def UploadPackage(self):
    """Uploads a package to Simian. To be implement in subclasses."""
    raise NotImplementedError

  def DownloadPackage(self):
    """Downloads a package from Simian."""
    filename = self.config['package']
    self.client.DownloadPackage(filename)
    print 'Package successfully downloaded!'

  def DeletePackage(self):
    """Deletes a package and associated pkginfo from Simian."""
    print 'Deleting package from Simian....'
    filename = self.config['package']
    self.client.DeletePackage(filename)
    print 'Package succesfully deleted!'

  def ListPackages(self):
    """Deletes a package and associated pkginfo from Simian."""
    print 'List packages on Simian....'
    install_types = self.config['install_types']
    catalogs = self.config['catalogs']
    print self.client.ListPackages(install_types, catalogs)
    print 'Complete!'

  def EditPackageInfo(self):
    """Edit a package info on Simian. To be implement in subclasses."""
    raise NotImplementedError

  def SetDebug(self, debug):
    """Set debug level and adjust exception handler output.

    Args:
      debug: bool, True if debug mode
    """
    def new_exc(msg, *args):
      logging.debug(msg, exc_info=sys.exc_info(), *args)
    logging.exception = new_exc

    if debug:
      logging.getLogger().setLevel(logging.DEBUG)
    else:
      logging.getLogger().setLevel(logging.WARN)

  def PrintError(self, errstr):
    print >>sys.stderr, 'Error: %s' % errstr

  def Run(self):
    """Run"""
    self.SetDebug(self.config['debug'] != False)

    if self.command is None:
      raise CliError('No command defined, run LoadArgs() first')

    # speedup, temporary hack until we clean up this cli handler like
    # simianauth.
    if self.command == 'help':
      self.Usage()
      return

    self.client = self.GetSimianClientInstance(self.config['server'])
    self._SetupProgressCallback()

    if self.COMMANDS[self.command].get('auth', None) == 'userauth':
      self.client.DoUserAuth()
    else:
      self.client.DoSimianAuth()

    method = getattr(self, self.COMMANDS[self.command]['method'])
    try:
      method()
    except (client.Error, Error), e:
      logging.exception(e)
      self.PrintError(e)


def main(argv, simian_cli_class=None):
  if simian_cli_class is None:
    if __name__ == '__main__':
      simian_cli_class = SimianCliClient
    else:
      raise Error('Must specify cli class to instantiate')

  c = simian_cli_class()

  try:
    c.LoadArgs(argv)
  except OptionError, e:
    c.Usage('Option error: %s' % str(e))
    sys.exit(1)

  try:
    c.Run()
  except (client.SimianClientError, Error, CliError), e:
    c.PrintError(str(e))
    sys.exit(1)

  sys.exit(0)


if __name__ == '__main__':
  main(sys.argv)