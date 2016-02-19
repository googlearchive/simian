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
"""Simian network backoff detection module."""


import logging
import platform
import re
import socket
import urlparse
import requests


from simian.mac.client import flight_common

LINUX = 'Linux'
DARWIN = 'Darwin'
PLATFORM = platform.system()

ROUTE = {LINUX: ['/sbin/ip', 'route'], DARWIN: ['/usr/sbin/netstat', '-nr']}
ARP = {LINUX: '/usr/sbin/arp', DARWIN: '/usr/sbin/arp'}
HOST = '/usr/bin/host'
IFCONFIG = '/sbin/ifconfig'

IOS_WAP_DEFAULT_GATEWAY_IP = '172.20.10.1'
IOS_WAP_NETWORK_GATEWAY_SUBNET = '172.20.10/28'

INTERFACE_ANDROID_WAP = 'android_wap'
INTERFACE_WWAN = 'wwan'
INTERFACE_VPN = 'vpn'

BACKOFF_WLANS = frozenset([
    'Fly-Fi',
    'gogoinflight',
    'Telekom_FlyNet',
    'United_WiFi',
    'United_Wi-Fi',
])


def _GetPlatform():
  """Returns a str like constants LINUX or DARWIN."""
  platform_str = platform.system()
  assert platform_str in [LINUX, DARWIN]
  return platform_str


def GetAllInterfaceNames():
  """Get network interfaces info for this host.

  Note that this list may include all types of interfaces
  that are not normally interesting to this script, e.g. fw0.

  Returns:
    list, e.g. ['en0', 'en1', 'fw0', 'eth0']
  """
  this_platform = _GetPlatform()

  # Note slight difference in regex.
  # BSD ifconfig writes "interface_name:\s+"
  # while Linux writes "interface_name\s+"
  if this_platform == LINUX:
    intf_header = re.compile(r'^([a-z]+(?:[0-9]+)?)\s+')
  elif this_platform == DARWIN:
    intf_header = re.compile(r'^([a-z]+(?:[0-9]+)?):\s+')

  return_code, stdout, stderr = flight_common.Exec('/sbin/ifconfig')
  if return_code != 0 or stderr:
    return []

  interfaces = []

  if stdout:
    for l in stdout.splitlines():  # pylint: disable=maybe-no-member
      m = intf_header.search(str(l))
      if m:
        interfaces.append(m.group(1))

  return interfaces


def GetInterfaceNames(interface_type):
  """Get the network interface names for an interface type.

  Args:
    interface_type: str, like INTERFACE_* constant
  Returns:
    list of str, like ['ppp0'] or ['en0', 'en1']
  Raises:
    ValueError: if interface_type is unknown
    PlatformError: if platform is not implemented
  """
  this_platform = _GetPlatform()
  all_interfaces = GetAllInterfaceNames()

  if interface_type == INTERFACE_WWAN:
    return [x for x in all_interfaces if x.startswith('ppp')
            or x.startswith('bnep')]
  elif interface_type == INTERFACE_ANDROID_WAP:
    if this_platform == DARWIN:
      return [x for x in all_interfaces if x.startswith('en')]
    elif this_platform == LINUX:
      return [x for x in all_interfaces if x.startswith('wlan')]
  elif interface_type == INTERFACE_VPN:
    if this_platform in [DARWIN, LINUX]:
      return [x for x in all_interfaces if x.endswith('tun0')]
    else:
      raise ValueError('Unknown Platform: %s' % this_platform)
  else:
    raise ValueError(interface_type)


def GetNetworkGateway(network):
  """Get the gateway for a network.

  Uses "netstat -nr" on Darwin and "ip route" on Linux to read the routing
  table.

  It searches for a route with destination exactly matching the network
  parameter!

  Args:
    network: str, likely in CIDR format or default gateway,
        e.g. "1.2.3/24" or "0.0.0.0"
  Returns:
    a string like "1.2.3.4" or "link#1" or "01:02:03:04:05:06" or
    "dev wlan0", depending on the type of route and platform.
  """
  route = ROUTE.get(_GetPlatform(), None)
  logging.debug('Route: %s', str(route))
  if not route:
    return

  try:
    return_code, stdout, stderr = flight_common.Exec(route)
  except OSError:
    return_code = None

  if return_code != 0 or stderr or not stdout:
    return

  gateway_pattern = (
      r'^%s\s+(via[\s\t])?'
      r'([\d\.]+|[0-9a-f:]+|link#\d+|dev [a-z\d]+)[\s\t]+' % network)
  gateway = re.search(gateway_pattern, str(stdout), re.MULTILINE)

  if gateway:
    return gateway.group(2)

  return


def GetDefaultGateway():
  """Gets the default gateway.

  Returns:
    a string like "192.168.0.1" or None if default gateway is unknown.
  """
  if _GetPlatform() in [DARWIN, LINUX]:
    default = 'default'
  else:
    logging.error('Unknown platform %s', _GetPlatform())

  return GetNetworkGateway(default)


def GetHttpResource(host, path='/', port=80, redir=False):
  """Gets HTTP resource.

  Args:
    host: str, like "example.com", but not "http://example.com".
    path: optional, str, like "/path", default "/".
    port: optional, int, default 80.
    redir: optional, bool, whether to follow redirects.
  Returns:
    (int response code, str response body)
    (int -1, str error from http exception)
  """
  if port != 80:
    port_str = ':%d' % port
  else:
    port_str = ''
  url = 'http://%s%s' % (host, port_str)
  url = urlparse.urljoin(url, path)
  try:
    response = requests.get(url, allow_redirects=redir)
    code = response.status_code
    body = response.text
    return code, body
  except requests.RequestException as e:
    return -1, str(e)


def IsOnWwan():
  """"Checks WWAN device connection status.

  Note: this may produce false-positives, and may not catch all WWAN
    devices.  Several Sprint and Verizon devices were tested, all of which
    create ppp0 upon connection.  However, L2TP VPN also creates ppp0
    (Google no longer uses this as of Q2-2010 in favor of SSLVPN).  A
    stronger check is probably needed at some point.

    As of 2011-12-6 OpenVPN interface is tun0 on Linux and Darwin.

  Returns:
    Boolean. True if WWAN device is active, False otherwise.
  """
  wwan_ifaces = GetInterfaceNames(INTERFACE_WWAN)
  for wwan_iface in wwan_ifaces:
    try:
      return_code, unused_out, unused_err = flight_common.Exec(
          [IFCONFIG, wwan_iface])
    except OSError:
      return_code = None

    # ifconfig exits with 1 if interface doesn't exist.
    if return_code == 0:
      return True

  return False


def GetNetworkName():
  """Return network name (SSID for WLANs) a device is connected to.

  Returns:
    name of the matching network name if possible, None otherwise.
  """
  this_platform = _GetPlatform()
  if this_platform == LINUX:
    cmdline = '/usr/bin/nmcli -t -f NAME,DEVICES conn status'
    # Ignore "Auto " prefix on automatically connecting networks.
    ssid_re = re.compile(r'^(Auto )?([^:]*):.*$')
    try:
      return_code, out, _ = flight_common.Exec(cmdline)
    except OSError:
      logging.exception('Error executing nmcli')
      return

    if out and not return_code:
      for l in out.splitlines():
        res = ssid_re.match(l)
        if res:
          return res.groups()[1]

  elif this_platform == DARWIN:
    cmdline = (
        '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/'
        'Current/Resources/airport -I | '
        'awk \'/ SSID/ {print substr($0, index($0, $2))}\'')
    try:
      return_code, out, _ = flight_common.Exec(cmdline)
    except OSError:
      logging.exception('Error executing airport')
      return
    if out and not return_code:
      return out.strip() or None


def IsOnBackoffWLAN():
  """Returns True if on a Backoff WLAN, such as gogoinflight WiFi."""
  return GetNetworkName() in BACKOFF_WLANS


def IsOnAndroidWap():
  """Checks if Android WiFi or Bluetooth tethering is connected.

  Returns:
    Boolean. True if Android tethering is connected, False otherwise.
  """
  # ifconfig output looks a little bit different on Darwin vs Linux.
  #
  # Darwin:
  # inet 169.254.135.20 netmask 0xffff0000 broadcast 169.254.255.255
  # Linux:
  # inet addr:172.26.113.45  Bcast:172.26.115.255  Mask:255.255.252.0
  android_wap_match_regex = re.compile(
      r'inet[\w\s]*[\s:]+192\.168\.(42|43|44)\.\d{1,3}\s+'
      r'.*(?:netmask\s+0xffffff00\s+|Mask:255\.255\.255\.0)')

  ifaces = GetInterfaceNames(INTERFACE_ANDROID_WAP)

  for wifi_iface in ifaces:
    # Android tethering uses very specific subnets*, as well as dnsmasq which
    # reveals itself via the TXT VERSION.BIND record.
    # * 192.168.42.0/24 for wired, 192.168.43.0/24 for WiFi, and
    #   192.168.44.0/24 for Bluetooth.
    try:
      return_code, stdout, stderr = flight_common.Exec([IFCONFIG, wifi_iface])
    except OSError:
      return_code = None

    if return_code != 0 or stderr:  # interface was likely not found.
      continue

    android_wap_match = android_wap_match_regex.search(stdout)

    # Look for an interface on 192.168.4[2-4].0/24.
    if android_wap_match is not None:
      # If the default gateway is not through a likely Android WAN interface,
      # tethering may be active but is not likely to be used.
      default_gateway = GetDefaultGateway()
      logging.debug('Default gateway: %s', str(default_gateway))
      default_gateway_prefix = '192.168.%s.' % android_wap_match.group(1)
      if not default_gateway.startswith(default_gateway_prefix):
        return False

      # IP, netmask, gateway look like Android WAP, so check dnsmasq.

      # Request needs to be explicitly top level, as Linux uses
      # ndots:2 which would turn VERSION.BIND (without trailing dot) into
      # VERSION.BIND.foo.example.com in some cases.
      cmd = [HOST, '-W', '5', '-c', 'CHAOS', '-t', 'txt', 'VERSION.BIND.',
             default_gateway]
      try:
        return_code, stdout, unused_err = flight_common.Exec(cmd)
      except OSError:
        return_code = None
      if return_code != 0:
        continue
      dnsmasq_match = re.search(
          r'VERSION\.BIND descriptive text "dnsmasq-.*"', stdout)
      if dnsmasq_match is not None:
        # IP, netmask and dnsmasq all match Android WAP tethering.
        return True

  return False


def IsOnIosWap():
  """Checks if the wireless connection is to an iOS WAP tether.

  Returns:
    Boolean. True if iOS WAP is connected, False otherwise.
  """
  # iOS WAP looks like a 172.20.10/28 network. Gateway is
  # 172.20.10.1 with TCP port 62078 open.
  gateway = GetNetworkGateway(IOS_WAP_NETWORK_GATEWAY_SUBNET)
  if not gateway:
    return False

  ip = GetDefaultGateway()
  if not ip:
    return False

  if ip != IOS_WAP_DEFAULT_GATEWAY_IP:
    return False

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  result = sock.connect_ex((ip, 62078))
  if result == 0:
    return True

  return False


def IsOnMifi():
  """Checks if the wireless connection is to a MiFi-like device.

  These devices are available from Verizon, Sprint, others, and usually
  offer some kind of web access portal that says MiFi or Jetpack as a text
  string.

  Returns:
    Bool, True if the connection is a likely MiFi-like device, False if not.
  """
  ip = GetDefaultGateway()
  if not ip:
    return False

  if ip.startswith('192.168.1.'):  # Verizon and Sprint devices
    http_status, body = GetHttpResource(ip, redir=True)
    # MiFi-like devices usually run a http interface. It returns a long http
    # response with various easily found "MiFi" or "Jetpack" strings in it
    # when loaded. No http auth challenge is issued.
    if http_status == 200 and body and ('MiFi' in body or 'Jetpack' in body):
      return True
  elif ip == '192.168.8.1':  # common Huawei gateway
    http_status, _ = GetHttpResource(ip, redir=False)
    return http_status == 307

  return False
