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


"""A list of supported hash functions."""

import hashlib


class HashType:
  """A wrapper around a hash function."""

  def __init__(self, bit_length: int, name: str):
    self.bit_length = bit_length
    self.name = name

  def hash(self, data: bytes) -> int:
    """Hashes a sequence of bytes to an integer."""
    hasher = hashlib.new(self.name)
    hasher.update(data)
    return int(hasher.hexdigest(), 16)


HashType.SHA256 = HashType(256, 'sha256')
HashType.SHA384 = HashType(384, 'sha384')
HashType.SHA512 = HashType(512, 'sha512')
