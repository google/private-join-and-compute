# Copyright 2019 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Module providing conversion functions like long to bytes or bytes to long."""

import operator
import struct

import six


def _PadZeroBytes(byte_str, blocksize):
  """Pads the front of byte_str with binary zeros.

  Args:
    byte_str: byte string to pad the binary zeros.
    blocksize: the byte_str will be padded so that the length of the output will
      be a multiple of blocksize.

  Returns:
    a new byte string padded with binary zeros if necessary.
  """
  if len(byte_str) % blocksize:
    return (blocksize - len(byte_str) % blocksize) * b'\000' + byte_str
  return byte_str


def LongToBytes(number: int, blocksize: int = 0) -> bytes:
  """Converts an arbitrary length number to a byte string.

  Args:
    number: number to convert to bytes.
    blocksize: if specified, the output bytes length will be a multiple of
      blocksize.

  Returns:
    byte string for the number.

  Raises:
    ValueError: when the number is negative.
  """
  if number < 0:
    raise ValueError('number needs to be >=0, given: {}'.format(number))
  number_32bitunit_components = []
  while number != 0:
    number_32bitunit_components.insert(0, number & 0xFFFFFFFF)
    number >>= 32
  converter = struct.Struct('>' + str(len(number_32bitunit_components)) + 'I')
  n_bytes = six.ensure_binary(converter.pack(*number_32bitunit_components))
  for idx in range(len(n_bytes)):
    if operator.getitem(n_bytes, idx) != 0:
      break
  else:
    n_bytes = b'\000'
    idx = 0
  n_bytes = n_bytes[idx:]
  if blocksize > 0:
    n_bytes = _PadZeroBytes(n_bytes, blocksize)
  return six.ensure_binary(n_bytes)


def BytesToLong(byte_string: bytes) -> int:
  """Converts given byte string to a long."""
  result = 0
  padded_byte_str = _PadZeroBytes(byte_string, 4)
  component_length = len(padded_byte_str) // 4
  converter = struct.Struct('>' + str(component_length) + 'I')
  unpacked_data = converter.unpack(padded_byte_str)
  for i in range(0, component_length):
    result += unpacked_data[i] << (32 * (component_length - i - 1))
  return result
