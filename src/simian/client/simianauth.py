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

"""Slim py binary for fetching a Simian Auth token.

Note: Currently this relies on Puppet SSL certs, so it only works on Goobuntu
and gMac, not gWindows.
"""



import cPickle as pickle
import datetime
import getopt
import logging
import os
import sys
import tempfile
from simian.auth import settings as auth_settings
from simian.client import client


class Error(Exception):
  """Base error."""


class OptionError(Error):
  """An error occured while parsing options."""


class FailWithLogoutError(Error):
  """An error occured which should stop client processing, but a
  logout, if necessary, should be attempted."""


class UnknownReportFormatError(Error):
  """Report has unknown, unparseable format."""


class SimianAuthCliClient(object):
  """SimianAuth CLI client class.

  Generic functionality for all CLI clients goes here.  Don't put anything
  OS specific in this class.
  """

  # name of this tool
  NAME = 'simianauth'

  # suggested order: commands first, then command options.
  LONGOPTS = [
      'help',
      'debug',
      'login',
      'report=',
      'write-root-ca-certs=',
      'server=',
      'token=',
      'logout',
      'print-cookie',
  ]

  # no short options
  SHORTOPTS = ''

  # commands and their required options and handler method
  COMMANDS = {
      'help': {
          'method': 'Usage',
          'noclient': True,
          'auth': 'none',
      },
      'logout': {
          'method': 'Logout',
          'auth': 'none',
      },
      'login': {
          'method': 'Login',
      },
      'report': {
          'method': 'Report',
      },
      'write-root-ca-certs': {
          'method': 'WriteRootCaCerts',
          'noclient': False,
          'auth': 'none',
      },
      'print-cookie': {
          'method': 'PrintTokenCookie',
      },
  }

  DEFAULT_COMMAND = 'login'

  # usage text
  # TODO: make usage more easily updated from subclasses.
  USAGE = """
    Simian client

    usage: %s [command] [command_options] ...

    --login
        login to the Simian server (obtain a token)
    --print-cookie
        optional param to output the obtained token cookie to stdout
    --logout
        logout from Simian server

    --report [report]
        report to the Simian server,

        where report is a string in format:
            "body:URLENCODED_PARAMS"
            "dict:REPORT_TYPE:KEY1=VALUE2:KEY2=VALUE2:..."
            "pickle:REPORT_TYPE:PICKLED_PARAMS"

        the report string above may be prepended with a feedback request
        in the format:
            "feedback:STRING_FROM_SERVER=EXIT_STATUS: ..."

        e.g.

            "feedback:FORCE_CONTINUE=9:body:URLENCODED_PARAMS"

        Will cause simianauth to exit with status 9 if FORCE_CONTINUE is
        received for this report.

    --write-root-ca-certs [filename]
        write the root CA certs that Simian client is using to filename.
        existing file is destroyed.

    --token [token string]
        specify token

    --server [hostname]
        alternative Simian server to contact

    --debug
        output debugging information
    --help
        this text
  """ % NAME

  def __init__(self):
    self.opts = []
    self.args = []
    self.config = {
      'debug': False,
      'server': None,
      'report': [],
      'token': None,
      'token_cookie': None,
      'write-root-ca-certs': None,
    }
    self.client = None
    self.commands = None

  def GetSimianClientInstance(self, *args, **kwargs):
    """Returns an instance of the Simian client to use within this CLI.

    CLI subclasses should override this if necessary.
    """
    return client.SimianAuthClient(*args, **kwargs)

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

  def _OrderCommands(self, commands):
    """Order list of commands into proper order and include prerequisites.

    Args:
      commands: list, of commands intended to run
    Returns:
      None
    """
    def __cmp(cmd1, cmd2):
      if cmd1 == 'login':
        return -1
      elif cmd1 == 'logout':
        return 1
      elif cmd2 == 'logout':
        return -1
      else:
        return 0

    commands.sort(cmp=__cmp)

    # if report command, and no token specified, add
    # login and logout commands to obtain a token.
    if commands == ['report']:
      if not self.config['token']:
        commands.insert(0, 'login')
        commands.append('logout')

  def _LoadConfig(self):
    """Given parsed options, load them into the config.

    Raises:
      OptionError: if inconsistent or missing options have been specified
    """
    found_cmd = []
    # load specified commands and options
    for (dashoptname, optval) in self.opts:
      optname = dashoptname[2:]
      if optname in self.config:
        if type(self.config[optname]) is list:
          self.config[optname].append(optval)
        else:
          self.config[optname] = optval
      if optname in self.COMMANDS and optname not in found_cmd:
        found_cmd.append(optname)

    self.SetDebug(self.config['debug'] != False)
    logging.debug('_LoadConfig(): config = %s', str(self.config))

    # if help is any command, make it the only command.
    if 'help' in found_cmd:
      found_cmd = ['help']

    # if no command specified, use the default.
    if not found_cmd:
      found_cmd.append(self.DEFAULT_COMMAND)

    self._OrderCommands(found_cmd)

    if len(found_cmd) < 1:
      raise OptionError('Must specify a command, one of: %s' % ' '.join(
          map(lambda x: '--%s' % x, self.COMMANDS.keys())))

    # make sure all of the required command options were supplied
    # or default values satisfy them
    for command in found_cmd:
      if 'require' in self.COMMANDS[command]:
        for req_cmdopt in self.COMMANDS[command]['require']:
          if req_cmdopt not in self.config or self.config[req_cmdopt] is None:
            raise OptionError('Must specify command option --%s' % req_cmdopt)

    # everything is fine, set the discovered command
    self.commands = found_cmd
    logging.debug('_LoadConfig(): commands = %s' % self.commands)

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

  def _PreprocessRunConfig(self):
    """Before Run() starts, last chance to preprocess the config."""

  def _SetTokens(self, token):
    """Sets 'token' and 'token_cookie' self.config keys based on passed token.

    Args:
      token: str token.
    """
    # if a cookie was supplied as the token, parse out the actual token.
    if token.startswith(auth_settings.AUTH_TOKEN_COOKIE):
      logging.debug('Setting token configs from: %s', token)
      self.config['token_cookie'] = token
      token = token[len(auth_settings.AUTH_TOKEN_COOKIE) + 1:]
      token = token.split(';', 1)[0]
      self.config['token'] = token

  def Run(self):
    """Run all commands."""
    if self.commands is None:
      raise Error('no command defined, run LoadArgs() first')

    if not self.commands:
      return

    self._PreprocessRunConfig()

    did_uauth = False
    did_auth = False

    command_idx = 0
    while command_idx < len(self.commands):
      command = self.commands[command_idx]

      if not self.COMMANDS[command].get('noclient', False):
        if self.client is None:
          self.client = self.GetSimianClientInstance(self.config['server'])

      logging.debug('Running command: "%s"', command)

      # a token was supplied, auth was already done in the past.
      # set the token into the auth class.
      if self.config['token']:
        did_auth = True
        did_uauth = True
        self._SetTokens(self.config['token'])
        self.client.SetAuthToken(self.config['token'])

      reqd_auth = self.COMMANDS[command].get('auth', None)
      if reqd_auth == 'uauth':
        if not did_uauth:
          self.client.DoUAuth()
          did_uauth = True
      elif reqd_auth == 'none':
        pass
      else:
        if not did_auth and command == 'login':
          did_auth = True

      method = getattr(self, self.COMMANDS[command]['method'])
      try:
        method()
      except FailWithLogoutError, e:
        # medium level severity error has occured.
        # if logout command was specified, do it now.
        if 'logout' in self.commands:
          self.commands = ['logout']
          command_idx = 0
          continue
        else:
          logging.exception(e)
          self.PrintError(e)
          break
      except (client.Error, Error), e:
        logging.exception(e)
        self.PrintError(e)
        break

      command_idx += 1

  def Login(self):
    """Login to Simian, get a token."""
    logging.debug('SimianAuthCliClient.Login')

    token = self.client.GetAuthToken()
    if not token:
      raise client.Error('Token empty')
    self._SetTokens(token)
    # if simianauth is executed without commands then print the token to stdout
    if len(self.commands) == 1:
      self.PrintTokenCookie()

  def PrintTokenCookie(self):
    """Prints the auth token to stdout."""
    print self.config['token_cookie']

  def WriteRootCaCerts(self):
    """Write the internal root CA certs to a file."""
    logging.debug('WriteRootCaCerts')

    if not self.config['write-root-ca-certs']:
      raise client.Error('Must specify filename for write-root-ca-certs')

    tmpfile = tempfile.NamedTemporaryFile(
        dir=os.path.dirname(
            os.path.realpath(self.config['write-root-ca-certs'])))
    tmpfile.write(self.client.GetSystemRootCACertChain())

    logging.debug('WriteRootCaCerts: writing to tmp %s', tmpfile.name)

    try:
      os.unlink(self.config['write-root-ca-certs'])
    except OSError:
      pass

    try:
      os.link(tmpfile.name, self.config['write-root-ca-certs'])
    except OSError, e:
      tmpfile.close()
      raise client.Error('Error writing root CA certs: %s' % str(e))

    tmpfile.close()
    logging.debug('WriteRootCaCerts: success')

  def Logout(self):
    """Logout from Simian, release a token."""
    logging.debug('SimianAuthCliClient.Logout')

    if not self.config['token']:
      raise client.Error('Token must be supplied to logout')
    if not self.client.LogoutAuthToken():
      raise client.Error('Logout failed')

  def _SplitReportOption(self, arg):
    """Given a report option, translate it into a type and params.

    Args:
      arg: str, argument supplied by user, e.g.
        body:URLENCODED_REPORT
        pickle:REPORT_TYPE:PICKLED_REPORT
        dict:REPORT_TYPE:foo=1:bar=2:zoo=3
    Returns:
      tuple of (report_type, params, feedback)
    Raises:
      UnknownReportFormatError: if an unknown report format was used
    """
    if not arg:
      raise UnknownReportFormatError(arg)

    report_type = None
    params = None
    feedback = None

    # parse leading feedback request
    if arg.startswith('feedback:'):
      a = arg.split(':')
      i = 1
      feedback = {}
      arg = arg[len('feedback:'):]
      while i < len(a) and a[i] not in ['body', 'dict', 'pickle']:
        k, v = a[i].split('=', 1)
        try:
          feedback[k] = int(v)
        except ValueError:
          raise UnknownReportFormatError('Value for %s must be int' % k)
        arg = arg[len(a[i]) + 1:]
        i += 1
      if not feedback:
        feedback = None

    # body: defines only params, already in url-encoded format
    if arg.startswith('body:'):
      (unused, params) = arg.split(':', 1)
      if params.find('_report_type=') < 0:
        raise UnknownReportFormatError('report does not contain _report_type')
      params = str(params)
      report_type = None
    # dict: defines report_type and N colon-sep key=value pairs
    elif arg.startswith('dict:'):
      a = arg.split(':')
      if len(a) >= 3:
        report_type = a[1]
        if report_type.find('=') > -1:
          raise UnknownReportFormatError('report_type must follow dict:')
        params = {}
        for kv in a[2:]:
          k, v = kv.split('=', 1)
          params[k] = v
    # pickle: defines report_type and params in pickled format
    elif arg.startswith('pickle:'):
      (unused, report_type, params) = arg.split(':', 2)
      params = pickle.loads(params)

    if params is None:
      raise UnknownReportFormatError(arg, params, feedback)
    else:
      return report_type, params, feedback

  def Report(self):
    """Report to Simian."""
    logging.debug('SimianAuthCliClient.Report %s', self.config['report'])

    for report in self.config['report']:
      report_type, params, feedback = self._SplitReportOption(report)
      logging.debug('Report(%s, %s, %s)', report_type, params, feedback)
      want_feedback = feedback is not None
      try:
        if report_type is None:
          response = self.client.PostReportBody(
              params, feedback=want_feedback)
        else:
          response = self.client.PostReport(
              report_type, params, feedback=want_feedback)
      except client.SimianServerError, e:
        raise FailWithLogoutError(e)

      if want_feedback:
        if response:
          response = response.strip()
          if response in feedback:
            logging.debug(
                'Exiting with status %d because of report feedback %s',
                feedback[response], response)
            sys.exit(feedback[response])

def main(argv, simian_cli_class=None):
  if simian_cli_class is None:
    if __name__ == '__main__':
      simian_cli_class = SimianAuthCliClient
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
  except client.SimianClientError, e:
    print >>sys.stderr, 'Error: %s' % str(e)
    sys.exit(1)

  sys.exit(0)


if __name__ == '__main__':
  main(sys.argv)