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


"""A list of supported elliptic curves."""


class SupportedCurve:
  """A SupportedCurve helper class.

  The class encapsulates a curve name as well as the curve ID, as encoded by
  the OpenSSL enum in openssl/ec.h.
  """

  def __init__(self, curve_name: str, curve_id: int):
    self.curve_name = curve_name
    self.id = curve_id


SupportedCurve.SECP256R1 = SupportedCurve('secp256r1', 415)
SupportedCurve.SECP384R1 = SupportedCurve('secp384r1', 715)
