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
"""App Engine Model Properties."""


from google.appengine.ext import db

from simian.mac.common import compress
from simian.mac.common import util


class SerializedProperty(db.TextProperty):
  """TextProperty class that serializes and deserializes data."""

  # pylint: disable=g-bad-name
  def get_value_for_datastore(self, model_instance):
    """Sends a serialized representation of self._obj to Datastore."""
    if self._obj is None:
      return None
    else:
      return db.Text(util.Serialize(self._obj))

  # pylint: disable=g-bad-name
  def __get__(self, model_instance, model_class):
    """Returns the already deserialized object."""
    value = super(SerializedProperty, self).__get__(
        model_instance, model_class)
    # __get__ super returns self when the model_instance is None, which happens
    # when the property is accessed by a static member of a class, as opposed to
    # by an instance. When this happens, return our class instance.
    if value is self:
      return self
    return self._obj

  # pylint: disable=g-bad-name
  def __set__(self, model_instance, value):
    """Deserializes db.Text values and simply sets other types to self._obj."""
    if value is None or value == '':
      super(SerializedProperty, self).__set__(model_instance, None)
    elif type(value) is db.Text:
      # If the value is is db.Text, deserialize it to init _obj.
      self._obj = util.Deserialize(value)
    else:
      # If the incoming value is a not db.Text, it's an obj so just store it.
      self._obj = value


class CompressedUtf8BlobProperty(db.BlobProperty):
  """BlobProperty class that compresses/decompresses seamlessly on get/set.

  This Property is compressed on every __set__ and decompressed on every __get__
  operation. This should be taken into consideration when performing certain
  operations, such as slicing.
  """

  # pylint: disable=g-bad-name
  def get_value_for_datastore(self, model_instance):
    """Compresses the blob value on it's way to Datastore."""
    value = super(CompressedUtf8BlobProperty, self).get_value_for_datastore(
        model_instance)
    if value is None:
      self.length = 0
    else:
      self.length = len(value)
    return db.Blob(
        compress.CompressedText(value, encoding='utf-8').Compressed())

  # pylint: disable=g-bad-name
  def __get__(self, model_instance, model_class):
    """Decompresses the blob value when the property is accessed."""
    value = super(CompressedUtf8BlobProperty, self).__get__(
        model_instance, model_class)
    # __get__ super returns self when the model_instance is None, which happens
    # when the property is accessed by a static member of a class, as opposed to
    # by an instance. When this happens, return our class instance.
    if value is self:
      return self
    return unicode(
        compress.CompressedText(value, encoding='utf-8')).encode('utf-8')

  # pylint: disable=g-bad-name
  def __set__(self, model_instance, value):
    """Compresses the value when the property is set."""
    if not value:
      self.length = 0
      super(CompressedUtf8BlobProperty, self).__set__(model_instance, value)
    else:
      self.length = len(value)
      value = compress.CompressedText(value, encoding='utf-8').Compressed()
      super(CompressedUtf8BlobProperty, self).__set__(model_instance, value)

  # pylint: disable=g-bad-name
  def __len__(self):
    """Returns the length of the uncompressed blob data."""
    return self.length
