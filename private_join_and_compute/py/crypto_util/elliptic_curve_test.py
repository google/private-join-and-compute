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

"""Test class for elliptic_curve module."""

import os
import random
import unittest
from unittest import mock

from private_join_and_compute.py.crypto_util import converters
from private_join_and_compute.py.crypto_util import ssl_util
from private_join_and_compute.py.crypto_util.elliptic_curve import ECKey
from private_join_and_compute.py.crypto_util.elliptic_curve import ECPoint
from private_join_and_compute.py.crypto_util.ssl_util import BigNum
from private_join_and_compute.py.crypto_util.ssl_util import TempBNs
from private_join_and_compute.py.crypto_util.supported_curves import SupportedCurve
from private_join_and_compute.py.crypto_util.supported_hashes import HashType


# Equivalent to C++ curve NID_X9_62_prime256v1
TEST_CURVE = SupportedCurve.SECP256R1
TEST_CURVE_ID = TEST_CURVE.id


class EllipticCurveTest(unittest.TestCase):

  def setUp(self):
    super(EllipticCurveTest, self).setUp()

  def testEcKey(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_key_same = ECKey(TEST_CURVE_ID, ec_key.priv_key_bytes)
    self.assertEqual(
        ssl_util.BnToBytes(ec_key.priv_key_bn),
        ssl_util.BnToBytes(ec_key_same.priv_key_bn),
    )
    self.assertEqual(ec_key.curve_id, ec_key_same.curve_id)
    self.assertEqual(ec_key.elliptic_curve, ec_key_same.elliptic_curve)

  @mock.patch(
      'private_join_and_compute.py.crypto_util.ssl_util.RandomOracle',
      lambda x, bit_length, hash_type=None: 2 * x,
  )
  def testHashToPoint(self):
    t = random.getrandbits(160)
    ec_key = ECKey(TEST_CURVE_ID)
    x, y = ec_key.elliptic_curve.HashToCurve(t)
    ECPoint.FromPoint(ec_key.elliptic_curve.group, x, y).CheckValidity()

  def testEcPointsMultiplicationWithAddition(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_point = ec_key.elliptic_curve.GetPointByHashingToCurve(10)
    ec_point_sum = ec_point + ec_point + ec_point
    with TempBNs(x=3) as bn:
      ec_point_mul = ec_point * bn.x
    self.assertEqual(ec_point_sum, ec_point_mul)
    self.assertNotEqual(ec_point, ec_point_mul)

  def testEcPointsInPlaceMult(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_point = ec_key.elliptic_curve.GetPointByHashingToCurve(10)
    with TempBNs(x=3) as bn:
      ec_point *= bn.x
    self.assertNotEqual(
        ec_key.elliptic_curve.GetPointByHashingToCurve(10), ec_point
    )

  def testEcPointsInPlaceAdd(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_point = ec_key.elliptic_curve.GetPointByHashingToCurve(10)
    ec_point += ec_key.elliptic_curve.GetPointByHashingToCurve(11)
    self.assertNotEqual(
        ec_key.elliptic_curve.GetPointByHashingToCurve(10), ec_point
    )

  def testEcCurveOrder(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_point = ec_key.elliptic_curve.GetPointByHashingToCurve(10)
    ec_point1 = ec_point * BigNum.FromLongNumber(3)
    ec_point2 = ec_point * BigNum.FromLongNumber(
        3 + ec_key.elliptic_curve.order
    )
    self.assertEqual(ec_point1, ec_point2)

  def testDecryptKey(self):
    ec_key = ECKey(TEST_CURVE_ID)
    ec_point = ec_key.elliptic_curve.GetPointByHashingToCurve(10)
    self.assertEqual(
        ec_point, ec_point * ec_key.priv_key_bn * ec_key.decrypt_key_bignum
    )

  @mock.patch(
      'private_join_and_compute.py.crypto_util.ssl_util.BigNum'
      '.GenerateRandWithStart'
  )
  def testGetRandomGenerator(self, gen_rand):
    gen_rand.return_value = BigNum.FromLongNumber(2)
    ec_key = ECKey(TEST_CURVE_ID)
    g1 = ec_key.elliptic_curve.GetRandomGenerator()
    self.assertFalse(g1.IsAtInfinity())
    self.assertTrue(g1.IsOnCurve())
    gen_rand.return_value = BigNum.FromLongNumber(4)
    g2 = ec_key.elliptic_curve.GetRandomGenerator()
    self.assertFalse(g2.IsAtInfinity())
    self.assertTrue(g2.IsOnCurve())
    self.assertEqual(g2, g1 + g1)


if __name__ == '__main__':
  unittest.main()
