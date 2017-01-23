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
"""Utility functions."""

import datetime
import json
import os
import urllib

from simian.mac import common


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
  def utcfromtimestamp(cls, timestamp, allow_future=False):
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


def Serialize(obj):
  """Return a binary serialized version of object.

  Depending on the serialization method, some complex objects or input
  formats may not be serializable.

  UTF-8 strings (by themselves or in other structures e.g. lists) are always
  supported.

  Args:
    obj: any object
  Returns:
    str, possibly containing ascii values >127
  Raises:
    SerializeError: if an error occured during serialization
  """
  try:
    return json.dumps(obj)
  except TypeError as e:
    raise SerializeError(e)


def Deserialize(s, parse_float=float):
  """Return an object for a binary serialized version.

  Depending on the target platform, precision of float values may be lowered
  on deserialization.  Use parse_float to provide an alternative
  floating point translation function, e.g. decimal.Decimal, if retaining
  high levels of float precision (> ~10 places) is important.


  Args:
    s: str
    parse_float: callable, optional, to translate floating point values
  Returns:
    any object that was serialized
  Raises:
    DeserializeError: if an error occured during deserialization
  """
  try:
    if s is None:
      raise DeserializeError('Nothing to deserialize: %s' % type(s))
    return json.loads(s, parse_float=parse_float)
  except ValueError as e:
    raise DeserializeError(e)


def UrlUnquote(s):
  """Return unquoted version of a url string."""
  return urllib.unquote(s)


def MakeTrackMatrix(tracks, proposed_tracks=None):
  """Generates dict of tracks with string values indicating track status.

  Args:
    tracks: list of tracks the package is currently in.
    proposed_tracks: list of tracks the package is proposed to be in.

  Returns:
    A dict of tracks with string values for status, these values are
    in turn used by CSS to display the tracks color coded by status. Values
    returned: current, proposed_in, proposed_out, not_in. These correspond
    to CSS classes .track.current, .track.proposed_in, .track.proposed_out,
    and .track.not_in.
  """
  track_matrix = {}
  tracks = frozenset(tracks)
  if proposed_tracks is not None:
    proposed_tracks = frozenset(proposed_tracks)
    for track in common.TRACKS:
      if track in tracks and track in proposed_tracks:
        track_matrix[track] = 'current'
      elif track in tracks:
        track_matrix[track] = 'proposed_out'
      elif track in proposed_tracks:
        track_matrix[track] = 'proposed_in'
      else:
        track_matrix[track] = 'not_in'
  else:
    for track in common.TRACKS:
      if track in tracks:
        track_matrix[track] = 'current'
      else:
        track_matrix[track] = 'not_in'
  return track_matrix


def GetBlobstoreGSBucket():
  """GS Bucket For Blobsore.

  Returns:
    GS Bucket Name in case we want to use Blobstore API with Google Cloud
    Storage, None otherwise.
  """
  return os.environ.get('BLOBSTORE_GS_BUCKET')
