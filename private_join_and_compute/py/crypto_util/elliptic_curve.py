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

"""Module for elliptic curve related classes."""

import ctypes
from typing import Optional, Union

from private_join_and_compute.py.crypto_util import converters
from private_join_and_compute.py.crypto_util import ssl_util
from private_join_and_compute.py.crypto_util.ssl_util import BigNum
from private_join_and_compute.py.crypto_util.ssl_util import OpenSSLHelper
from private_join_and_compute.py.crypto_util.ssl_util import TempBNs
from private_join_and_compute.py.crypto_util.supported_curves import SupportedCurve
from private_join_and_compute.py.crypto_util.supported_hashes import HashType
import six

POINT_CONVERSION_COMPRESSED = 2


class ECPoint(object):
  """The ECPoint class."""

  def __init__(self, group, ec_point_bn):
    self._group = group
    self._point = ec_point_bn
    self.ctx = OpenSSLHelper().ctx
    # So that garbage collection doesn't collect ssl before this object.
    self.ssl = ssl_util.ssl

  @classmethod
  def FromPoint(cls, group: int, x: int, y: int):
    """Creates an EC_POINT object with the given x, y affine coordinates.

    Args:
      group: the EC_GROUP for the given point's elliptic curve
      x: the x coordinate of the point as long value
      y: the y coordinate of the point as long value

    Returns:
      <x, y> ECPoint on the elliptic curve defined by group

    Raises:
      TypeError: If the x, y coordinates are not of type long.
    """
    ec_point = cls._EmptyPoint(group)
    with TempBNs(x=x, y=y) as bn:
      # pylint: disable=protected-access
      ssl_util.ssl.EC_POINT_set_affine_coordinates_GFp(
          group, ec_point._point, bn.x, bn.y, None
      )
      # pylint: enable=protected-access
    ec_point.CheckValidity()
    return ec_point

  @classmethod
  def FromLongOrBytes(cls, group: int, point_long_or_bytes: Union[int, bytes]):
    """Creates an EC_POINT object from its serialized bytes representation.

    Args:
      group: the EC_GROUP for the point's elliptic curve.
      point_long_or_bytes: the serialized bytes representations of the point.

    Returns:
      The point encoded by point_long_or_bytes

    Raises:
      ValueError: if point_long_or_bytes is not a valid encoding of a point
      from the EC group.
    """
    ec_point = cls._EmptyPoint(group)
    if isinstance(point_long_or_bytes, int):
      point_long_or_bytes = converters.LongToBytes(point_long_or_bytes)
    # pylint: disable=protected-access
    ssl_util.ssl.EC_POINT_oct2point(
        group,
        ec_point._point,
        point_long_or_bytes,
        len(point_long_or_bytes),
        None,
    )
    # pylint: enable=protected-access
    ec_point.CheckValidity()
    return ec_point

  @classmethod
  def GetPointAtInfinity(cls, group):
    p = ssl_util.ssl.EC_POINT_new(group)
    ssl_util.ssl.EC_POINT_set_to_infinity(group, p)
    return ECPoint(group, p)

  @classmethod
  def _EmptyPoint(cls, group):
    return ECPoint(group, ssl_util.ssl.EC_POINT_new(group))

  def __del__(self):
    self.ssl.EC_POINT_free(self._point)

  def CheckValidity(self):
    """Checks if this point is valid and can be multiplied with the key.

    If the point is corrupted as a result of a faulty computation, this might
    leak data about the key.

    Raises:
      ValueError: If the point is not on the curve or if the point is the
      neutral element.
    """
    if not self.IsOnCurve():
      raise ValueError('The point is not on the curve.')

    if self.IsAtInfinity():
      raise ValueError('The point is the neutral element.')

  def __mul__(self, scalar):
    new_ec_point = self._EmptyPoint(self._group)
    # pylint: disable=protected-access
    if isinstance(scalar, BigNum):
      ssl_util.ssl.EC_POINT_mul(
          self._group,
          new_ec_point._point,
          None,
          self._point,
          scalar._bn_num,
          self.ctx,
      )
    else:
      ssl_util.ssl.EC_POINT_mul(
          self._group, new_ec_point._point, None, self._point, scalar, self.ctx
      )
    # pylint: enable=protected-access
    return new_ec_point

  def __imul__(self, scalar):
    if isinstance(scalar, BigNum):
      # pylint: disable=protected-access
      ssl_util.ssl.EC_POINT_mul(
          self._group, self._point, None, self._point, scalar._bn_num, self.ctx
      )
      # pylint: enable=protected-access
    else:
      ssl_util.ssl.EC_POINT_mul(
          self._group, self._point, None, self._point, scalar, self.ctx
      )
    return self

  def __add__(self, ec_point):
    new_ec_point = self._EmptyPoint(self._group)
    # pylint: disable=protected-access
    ssl_util.ssl.EC_POINT_add(
        self._group, new_ec_point._point, self._point, ec_point._point, self.ctx
    )
    # pylint: enable=protected-access
    return new_ec_point

  def __iadd__(self, ec_point):
    # pylint: disable=protected-access
    ssl_util.ssl.EC_POINT_add(
        self._group, self._point, self._point, ec_point._point, self.ctx
    )
    # pylint: enable=protected-access
    return self

  def IsOnCurve(self) -> bool:
    return 1 == ssl_util.ssl.EC_POINT_is_on_curve(
        self._group, self._point, None
    )

  def IsAtInfinity(self) -> bool:
    return 1 == ssl_util.ssl.EC_POINT_is_at_infinity(self._group, self._point)

  def GetAsLong(self) -> int:
    return converters.BytesToLong(self.GetAsBytes())

  def GetAsBytes(self) -> bytes:
    buf_len = ssl_util.ssl.EC_POINT_point2oct(
        self._group, self._point, POINT_CONVERSION_COMPRESSED, None, 0, None
    )
    buf = ctypes.create_string_buffer(buf_len)
    ssl_util.ssl.EC_POINT_point2oct(
        self._group,
        self._point,
        POINT_CONVERSION_COMPRESSED,
        buf,
        buf_len,
        None,
    )
    return six.ensure_binary(buf.raw)

  def __eq__(self, other: 'ECPoint'):
    # pylint: disable=protected-access
    if isinstance(other, self.__class__):
      return 0 == ssl_util.ssl.EC_POINT_cmp(
          self._group, self._point, other._point, self.ctx
      )
    raise ValueError('Cannot compare ECPoint with type {}'.format(type(other)))
    # pylint: enable=protected-access

  def __ne__(self, other: 'ECPoint'):
    return not self.__eq__(other)

  def __str__(self):
    return str(self.GetAsLong())


class EllipticCurve(object):
  """Class for representing the elliptic curve."""

  def __init__(
      self,
      curve_id: Union[int, SupportedCurve],
      hash_type: Optional[HashType] = None,
  ):
    if isinstance(curve_id, SupportedCurve):
      curve_id = curve_id.id
    if hash_type is None:
      hash_type = HashType.SHA512
    self._hash_type = hash_type
    self._group = ssl_util.ssl.EC_GROUP_new_by_curve_name(curve_id)
    with TempBNs(p=None, a=None, b=None, order=None) as bn:
      ssl_util.ssl.EC_GROUP_get_curve_GFp(self._group, bn.p, bn.a, bn.b, None)
      ssl_util.ssl.EC_GROUP_get_order(
          self._group, bn.order, OpenSSLHelper().ctx
      )
      self._order = ssl_util.BnToLong(bn.order)
      self._p = ssl_util.BnToLong(bn.p)
      self._p_bn = BigNum.FromLongNumber(self._p)
      if not self._p_bn.IsPrime():
        raise ValueError(
            'Wrong curve parameters: p must be a prime. p: {}'.format(self._p)
        )
      self._a = ssl_util.BnToLong(bn.a)
      self._b = ssl_util.BnToLong(bn.b)
      self._p_sub_one_div_by_two = (self._p - 1) >> 1
    # So that garbage collection doesn't collect ssl before this object.
    self.ssl = ssl_util.ssl

  def __del__(self):
    self.ssl.EC_GROUP_free(self._group)

  def GetPointByHashingToCurve(self, m: Union[int, bytes]) -> ECPoint:
    """Hashes m into the elliptic curve."""
    return ECPoint.FromPoint(self.group, *self.HashToCurve(m))

  def GetPointFromLong(self, m_long: int) -> ECPoint:
    """Converts the given compressed point (m_long) into ECPoint."""
    return ECPoint.FromLongOrBytes(self.group, m_long)

  def GetPointFromBytes(self, m_bytes: bytes) -> ECPoint:
    """Converts the given compressed point (m_bytes) into ECPoint."""
    return ECPoint.FromLongOrBytes(self.group, m_bytes)

  def GetPointAtInfinity(self) -> ECPoint:
    """Gets a point at the infinity."""
    return ECPoint.GetPointAtInfinity(self.group)

  def GetRandomGenerator(self):
    ssl_point = ssl_util.ssl.EC_GROUP_get0_generator(self.group)
    generator = ECPoint(
        self.group, ssl_util.ssl.EC_POINT_dup(ssl_point, self.group)
    )
    generator *= BigNum.FromLongNumber(self.order).GenerateRandWithStart(
        BigNum.One()
    )
    return generator

  def ComputeYSquare(self, x: int):
    """Returns y^2 calculated with x^3 + ax + b."""
    return (x**3 + self._a * x + self._b) % self._p

  def HashToCurve(self, m: Union[int, bytes]):
    """ "Hash m to a point on the elliptic curve y^2 = x^3 + ax + b.

    To hash m to a point on the curve, the algorithm first computes an integer
    hash value x = h(m) and determines whether x is the abscissa of a point on
    the elliptic curve y^2 = x^3 + ax + b. If not, set x = h(x) and try again.

    Security:
    The number of operations required to hash a message m depends on m, which
    could lead to a timing attack.

    Args:
      m: long, int or str input

    Returns:
      A point (x, y) on this elliptic curve.
    """
    x = ssl_util.RandomOracle(m, self._p, hash_type=self._hash_type)
    y2 = self.ComputeYSquare(x)

    # y2 is a quadratic residue if y2^(p-1)/2 = 1
    if 1 == ssl_util.ModExp(y2, self._p_sub_one_div_by_two, self._p):
      y2_bn = ssl_util.BigNum.FromLongNumber(y2).Mutable()
      y2_bn.IModSqrt(self._p_bn)
      if y2_bn.IsBitSet(0):
        return (x, y2_bn.ModNegate(self._p_bn).GetAsLong())
      return (x, y2_bn.GetAsLong())
    else:
      return self.HashToCurve(x)

  def __eq__(self, other):
    # pylint: disable=protected-access
    if isinstance(other, self.__class__):
      return self._p == other._p and self._a == other._a and self._b == other._b
    raise ValueError(
        'Cannot compare EllipticCurve with type {}'.format(type(other))
    )
    # pylint: enable=protected-access

  @property
  def group(self):
    return self._group

  @property
  def order(self):
    return self._order


class ECKey(object):
  """Class representing the elliptic curve key."""

  def __init__(
      self,
      curve_id: Union[int, SupportedCurve],
      priv_key_bytes: Optional[bytes] = None,
      hash_type: Optional[HashType] = None,
  ):
    if isinstance(curve_id, SupportedCurve):
      curve_id = curve_id.id
    self._curve_id = curve_id
    self._key = ssl_util.ssl.EC_KEY_new_by_curve_name(curve_id)
    if priv_key_bytes:
      ssl_util.ssl.EC_KEY_set_private_key(
          self._key, ssl_util.BytesToBn(priv_key_bytes)
      )
    else:
      if 1 != ssl_util.ssl.EC_KEY_generate_key(self._key):
        raise Exception('EC key generation failed.')
      self._Check()
    self._priv_key_bn = ssl_util.ssl.EC_KEY_get0_private_key(self._key)
    self._priv_key_bytes = ssl_util.BnToBytes(self._priv_key_bn)
    self._priv_key_bignum = BigNum.FromBytes(self._priv_key_bytes)
    self._ec = EllipticCurve(curve_id, hash_type=hash_type)
    self._decrypt_key = self._priv_key_bignum.ModInverse(
        BigNum.FromLongNumber(self._ec.order)
    )
    # So that garbage collection doesn't collect ssl before this object.
    self.ssl = ssl_util.ssl

  def __del__(self):
    self.ssl.EC_KEY_free(self._key)

  def _Check(self):
    if 0 == ssl_util.ssl.EC_KEY_check_key(self._key):
      raise ValueError('The ECKey checks has failed.')

  @property
  def priv_key_bytes(self):
    return self._priv_key_bytes

  @property
  def priv_key_bn(self):
    return self._priv_key_bn

  @property
  def priv_key_bignum(self):
    return self._priv_key_bignum

  @property
  def decrypt_key_bignum(self):
    return self._decrypt_key

  @property
  def elliptic_curve(self):
    return self._ec

  @property
  def curve_id(self):
    return self._curve_id
