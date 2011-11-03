#!/usr/bin/env python
# 
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Utility functions."""




import datetime
import cPickle as pickle
import re
import time


USE_JSON = False
json = None

# GAE
try:
  from django.utils import simplejson as json
  USE_JSON = True
except ImportError:
  pass

# python >2.6
try:
  import json
  USE_JSON = True
except ImportError:
  pass

# other
try:
  if not json:
    import simplejson as json
    USE_JSON = True
except ImportError:
  pass

# note: enabling pickle is not recommended, it can be insecure on the
# deserialize side!
USE_PICKLE = False
PICKLE_RE = re.compile(
    r'^(\(dp[01]|\(lp[01]|S\'|I\d|ccopy_reg|c.*p1).*\.$',
    re.MULTILINE|re.DOTALL)


class Error(Exception):
  """Base error."""


class SerializeError(Error):
  """Error during serialization."""


class DeserializeError(Error):
  """Error during deserialization."""


class EpochValueError(Error):
  """Error for epoch to datetime conversion problems."""


class EpochFutureValueError(EpochValueError):
  """An epoch time is in the future."""


class EpochExtremeFutureValueError(EpochFutureValueError):
  """An epoch time extremely too far in the future."""


class Datetime(object):
  """Datetime class for extending utcfromtimestamp()."""

  @classmethod
  def utcfromtimestamp(self, timestamp, allow_future=False):
    """Converts a str or int epoch time to datetime.

    Note: this method drops ms from timestamps.

    Args:
      timestamp: str, int, or float epoch timestamp.
      allow_future: boolean, default False, True to allow future timestamps.
    Returns:
      datetime representation of the timestamp.
    Raises:
      ValueError: timestamp is invalid.
      EpochValueError: the timestamp is valid, but unacceptable.
      EpochFutureValueError: timestamp under an hour in future.
      EpochExtremeFutureValueError: timestamp over an hour in future.
    """
    try:
      timestamp = int(float(timestamp))
      dt = datetime.datetime.utcfromtimestamp(timestamp)
    except (TypeError, ValueError):
      raise ValueError(
          'timestamp is None, empty, or otherwise invalid: %s' % timestamp)
    now = datetime.datetime.utcnow()
    if not allow_future and dt > now:
      msg = 'datetime in the future: %s' % dt
      if dt > (now + datetime.timedelta(minutes=66)):
        # raise a slightly different exception for > 66mins to allow for more
        # verbose logging.
        raise EpochExtremeFutureValueError(msg)
      raise EpochFutureValueError(msg)
    return dt


def IpToInt(ip):
  """Return a integer for an IP string.

  Output is in network byte order.

  Args:
    ip: str, IP address, like "192.168.0.1"
  Returns:
    int
  """
  ip_int = 0
  a = map(int, ip.split('.'))
  for i in xrange(len(a)):
    ip_int += (a[i] << ((3-i)*8))
  return ip_int


def IpMaskToInts(ip_mask):
  """Transform a network/mask string into integers.

  Output is in network byte order.

  Args:
    ip_mask: str, IP address, like "192.168.0.0/24"
  Returns:
    (int ip, int mask)
  """
  (net, mask) = ip_mask.split('/')
  mask = int(mask)
  mask_int = ((2 ** mask) - 1) << (32 - mask)
  return IpToInt(net), mask_int


def IpMaskMatch(ip, ip_mask):
  """Check if an IP is inside an IP mask.

  Args:
    ip: str, like "192.168.0.1"
    ip_mask: str, like "192.168.0.0/24"
  Returns:
    True or False
  """
  (ip_int_mask, ip_int_mask_bits) = IpMaskToInts(ip_mask)
  ip_int = IpToInt(ip)
  return (ip_int & ip_int_mask_bits) == ip_int_mask


def Serialize(obj, _use_pickle=USE_PICKLE, _use_json=USE_JSON):
  """Return a binary serialized version of object.

  Depending on the serialization method, some complex objects or input
  formats may not be serializable.

  UTF-8 strings (by themselves or in other structures e.g. lists) are always
  supported.

  Args:
    obj: any object
    _use_pickle: bool, optional, whether to use pickle
    _use_json: bool, optional, whether to use json
  Returns:
    str, possibly containing ascii values >127
  Raises:
    SerializeError: if an error occured during serialization
  """
  try:
    if _use_json:
      return json.dumps(obj)
    elif _use_pickle:
      return pickle.dumps(obj)
    else:
      raise SerializeError('No available serialization formats')
  except (pickle.PicklingError, TypeError), e:
    raise SerializeError(e)


def Deserialize(
    s,
    parse_float=float,
    _use_pickle=USE_PICKLE, _use_json=USE_JSON, _pickle_re=PICKLE_RE):
  """Return an object for a binary serialized version.

  Depending on the target platform, precision of float values may be lowered
  on deserialization.  Use parse_float to provide an alternative
  floating point translation function, e.g. decimal.Decimal, if retaining
  high levels of float precision (> ~10 places) is important.


  Args:
    s: str
    parse_floats: callable, optional, to translate floating point values
    _use_pickle: bool, optional, whether to use pickle
    _use_json: bool, optional, whether to use json
    _pickle_re: re.RegexObject, optional, pattern to match pickle strs
  Returns:
    any object that was serialized
  Raises:
    DeserializeError: if an error occured during deserialization
  """
  try:
    if s is None:
      raise DeserializeError('Nothing to deserialize: %s' % type(s))
    elif _use_pickle and _pickle_re.match(s):
      return pickle.loads(s)
    elif _use_json:
      return json.loads(s, parse_float=parse_float)
    else:
      raise DeserializeError('Serialization format unknown')
  except (pickle.UnpicklingError, ValueError), e:
    raise DeserializeError(e)