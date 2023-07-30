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

"""EC based commutative cipher."""

from typing import Optional

from private_join_and_compute.py.crypto_util import elliptic_curve
from private_join_and_compute.py.crypto_util import supported_hashes

NID_secp224r1 = 713  # pylint: disable=invalid-name
DEFAULT_CURVE_ID = NID_secp224r1
POINT_CONVERSION_COMPRESSED = 2


class EcCipher(object):
  """A commutative cipher based on Elliptic Curves."""

  # key is an address.
  def __init__(
      self,
      curve_id: int = DEFAULT_CURVE_ID,
      private_key_bytes: Optional[bytes] = None,
      hash_type: Optional[supported_hashes.HashType] = None,
  ) -> None:
    """Generate a new EC key pair, if the key is not passed as a parameter.

    The private key is a random value and the private point is the result of
    performing a scalar point multiplication of that value with the curve's
    base point.

    Args:
      curve_id: the id of the curve to use, given as an int value.
      private_key_bytes: an ec key in bytes, if the key has already been
        generated.
      hash_type: the hash to use in order to map a string to the elliptic curve.

    Raises:
      TypeError: If curve_id is not an int.
      Exception: If the key could not be generated.
    """
    self._ec_key = elliptic_curve.ECKey(curve_id, private_key_bytes, hash_type)

  def Encrypt(self, id_bytes: bytes) -> bytes:
    """Hashes the client id to a point on the curve.

    It then encrypts the point by multiplying it with the private key.

    Args:
      id_bytes: a client id encoded as a string/byte value.

    Returns:
      the compressed encoded EC Point in bytes.

    Raises:
      TypeError: If id_bytes is not a str type.
    """
    ec_point = self._ec_key.elliptic_curve.GetPointByHashingToCurve(id_bytes)
    return self.EncryptPoint(ec_point)

  def EncryptPoint(self, ec_point) -> bytes:
    """Encrypts a point on the curve.

    Args:
      ec_point: the point to encrypt.

    Returns:
      the compressed encoded encrypted point in bytes
    """
    ec_point *= self._ec_key.priv_key_bn
    return ec_point.GetAsBytes()

  def ReEncrypt(self, enc_id_bytes: bytes) -> bytes:
    """Re-encrypts the id by multiplying with the private key.

    Args:
      enc_id_bytes: an encrypted client id as a bytes value.

    Returns:
      the compressed encoded re-encrypted EC Point in bytes.

    Raises:
      TypeError: If enc_id_bytes id is not a str type.
    """
    ec_point = self._ec_key.elliptic_curve.GetPointFromBytes(enc_id_bytes)
    return self.EncryptPoint(ec_point)

  @property
  def ec_key(self):
    return self._ec_key

  @property
  def elliptic_curve(self):
    return self._ec_key.elliptic_curve

  def DecryptReEncryptedId(self, reenc_id_bytes: bytes) -> bytes:
    """Decrypts a reencrypted id to its encrypted id form.

    Assuming reenc_id_bytes=E_k1(E_k2(m)) where E(.) is the ec_cipher and k1/k2
    are private keys. This function with decryption key, k1', returns E_k2(m) or
    with decryption key, k2', E_k1(m). Essentially this removes one layer of
    encryption from the reenc_id_bytes.

    This function *cannot* be applied to encrypted ids as the return value would
    be the message one-way hashed to a point on the curve.

    Args:
      reenc_id_bytes: a reencrypted client id, encoded with a key and then
        reencoded with another key.

    Returns:
      An encoded id in bytes.
    """
    ec_point = self._ec_key.elliptic_curve.GetPointFromBytes(reenc_id_bytes)
    ec_point *= self._ec_key.decrypt_key_bignum
    return ec_point.GetAsBytes()
