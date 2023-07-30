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


"""Test class for ssl_util module."""

import os
import unittest
from unittest import mock
from unittest.mock import call
from unittest.mock import patch

from private_join_and_compute.py.crypto_util import converters
from private_join_and_compute.py.crypto_util import ssl_util
from private_join_and_compute.py.crypto_util.ssl_util import PRNG
from private_join_and_compute.py.crypto_util.ssl_util import TempBNs


class SSLUtilTest(unittest.TestCase):

  def setUp(self):
    self.test_path = os.path.join(
        os.getcwd(), 'privacy/blinders/testing/data/random_oracle'
    )

  def testRandomOracleRaisesValueErrorForVeryLargeDomains(self):
    self.assertRaises(ValueError, ssl_util.RandomOracle, 1, 1 << 130048)

  def _GenericRandomTestForCasesThatShouldReturnOneNum(
      self, expected_value, rand_func, *args
  ):
    # There is at least %50 chance one iteration would catch the error if
    # rand_func also returns something outside the interval. Doing the same test
    # 20 times would increase the overall chance to %99.9999 in the worst case
    # scenario (i.e., the rand_func may return only one other element except the
    # the expected value).
    for _ in range(20):
      actual_value = rand_func(*args)
      self.assertEqual(
          actual_value,
          expected_value,
          'The generated rand is {} but should be {} instead.'.format(
              actual_value, expected_value
          ),
      )

  def testGetRandomInRangeSingleNumber(self):
    self._GenericRandomTestForCasesThatShouldReturnOneNum(
        2**30 - 1, ssl_util.GetRandomInRange, 2**30 - 1, 2**30
    )

  def testGetRandomInRangeMultipleNumbers(self):
    rand = ssl_util.GetRandomInRange(11111111111, 11111111111111111111111)
    self.assertTrue(11111111111 <= rand < 11111111111111111111111)  # pylint: disable=g-generic-assert

  def testModExp(self):
    self.assertEqual(1, ssl_util.ModExp(3, 4, 80))

  def testModInverse(self):
    self.assertEqual(5, ssl_util.ModInverse(2, 9))

  def testGetRandomInRangeReturnOnlyOneValueWhenIntervalIsOne(self):
    random = ssl_util.GetRandomInRange(99999999999999998, 99999999999999999)
    self.assertEqual(99999999999999998, random)

  def testGetRandomInRangeReturnsAValueInRange(self):
    random = ssl_util.GetRandomInRange(99999999999999998, 100000000000000000000)
    self.assertLessEqual(99999999999999998, random)
    self.assertLess(random, 100000000000000000000)

  @patch(
      'private_join_and_compute.py.crypto_util.ssl_util.ssl', wraps=ssl_util.ssl
  )
  def testTempBNsForValues(self, mocked_ssl):
    with TempBNs(x=10, y=20) as bn:
      self.assertEqual(10, ssl_util.BnToLong(bn.x))
      self.assertEqual(20, ssl_util.BnToLong(bn.y))
      x_addr = bn.x
      y_addr = bn.y
    self.assertEqual(2, mocked_ssl.BN_free.call_count)
    mocked_ssl.BN_free.assert_any_call(x_addr)
    mocked_ssl.BN_free.assert_any_call(y_addr)

  @patch(
      'private_join_and_compute.py.crypto_util.ssl_util.ssl', wraps=ssl_util.ssl
  )
  def testTempBNsForLists(self, mocked_ssl):
    with TempBNs(x=10, y=[20, 30], z=40) as bn:
      self.assertEqual(10, ssl_util.BnToLong(bn.x))
      self.assertEqual(20, ssl_util.BnToLong(bn.y[0]))
      self.assertEqual(30, ssl_util.BnToLong(bn.y[1]))
      self.assertEqual(40, ssl_util.BnToLong(bn.z))
      addrs = [bn.x, bn.y[0], bn.y[1], bn.z]
    self.assertEqual(4, mocked_ssl.BN_free.call_count)
    for addr in addrs:
      mocked_ssl.BN_free.assert_any_call(addr)

  @patch(
      'private_join_and_compute.py.crypto_util.ssl_util.ssl', wraps=ssl_util.ssl
  )
  def testTempBNsForBytes(self, mocked_ssl):
    with TempBNs(x='\001', y=['\002', '\003'], z='\004') as bn:
      self.assertEqual(1, ssl_util.BnToLong(bn.x))
      self.assertEqual(2, ssl_util.BnToLong(bn.y[0]))
      self.assertEqual(3, ssl_util.BnToLong(bn.y[1]))
      self.assertEqual(4, ssl_util.BnToLong(bn.z))
      addrs = [bn.x, bn.y[0], bn.y[1], bn.z]
    self.assertEqual(4, mocked_ssl.BN_free.call_count)
    for addr in addrs:
      mocked_ssl.BN_free.assert_any_call(addr)

  @patch(
      'private_join_and_compute.py.crypto_util.ssl_util.ssl', wraps=ssl_util.ssl
  )
  def testTempBNsForBytesOrLong(self, mocked_ssl):
    with TempBNs(x=1, y=['\002', 3], z='\004') as bn:
      self.assertEqual(1, ssl_util.BnToLong(bn.x))
      self.assertEqual(2, ssl_util.BnToLong(bn.y[0]))
      self.assertEqual(3, ssl_util.BnToLong(bn.y[1]))
      self.assertEqual(4, ssl_util.BnToLong(bn.z))
      addrs = [bn.x, bn.y[0], bn.y[1], bn.z]
    self.assertEqual(4, mocked_ssl.BN_free.call_count)
    for addr in addrs:
      mocked_ssl.BN_free.assert_any_call(addr)

  def testTempBNsRaisesAssertionErrorWhenAListIsEmpty(self):
    self.assertRaises(AssertionError, TempBNs, x=10, y=[20, 30], z=[])

  def testTempBNsRaisesAssertionErrorWhenAlreadySetKeyUsed(self):
    self.assertRaises(AssertionError, TempBNs, _args=10)

  def testBigNumInitializes(self):
    big_num = ssl_util.BigNum.FromLongNumber(1)
    self.assertEqual(1, big_num.GetAsLong())

  def testOpenSSLHelperIsSingleton(self):
    helper1 = ssl_util.OpenSSLHelper()
    helper2 = ssl_util.OpenSSLHelper()
    self.assertIs(helper1, helper2)

  def testBigNumGeneratesSafePrime(self):
    big_prime = ssl_util.BigNum.GenerateSafePrime(100)
    self.assertTrue(
        big_prime.IsPrime()
        and (
            big_prime.SubtractOne() / ssl_util.BigNum.FromLongNumber(2)
        ).IsPrime()
    )
    self.assertEqual(100, big_prime.BitLength())

  def testBigNumIsSafePrime(self):
    prime = ssl_util.BigNum.FromLongNumber(23)
    self.assertTrue(prime.IsSafePrime())
    prime = ssl_util.BigNum.FromLongNumber(29)
    self.assertFalse(prime.IsSafePrime())

  def testBigNumGeneratesPrime(self):
    big_prime = ssl_util.BigNum.GeneratePrime(100)
    self.assertTrue(big_prime.IsPrime())
    self.assertEqual(100, big_prime.BitLength())

  def testBigNumGeneratesPrimeForSubGroup(self):
    prime = ssl_util.BigNum.GeneratePrime(50)
    big_prime = prime.GeneratePrimeForSubGroup(100)
    self.assertTrue(big_prime.IsPrime())
    self.assertEqual(ssl_util.BigNum.One(), big_prime % prime)
    self.assertEqual(100, big_prime.BitLength())

  def testBigNumBitLength(self):
    big_prime = ssl_util.BigNum.FromLongNumber(15)
    self.assertEqual(4, big_prime.BitLength())
    big_prime = ssl_util.BigNum.FromLongNumber(16)
    self.assertEqual(5, big_prime.BitLength())

  def testBigNumAdds(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num3 = big_num1 + big_num2
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(5, big_num3.GetAsLong())

  def testBigNumAddsInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num1 += big_num2
    self.assertEqual(5, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())

  def testBigNumSubtracts(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(4)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num3 = big_num1 - big_num2
    self.assertEqual(4, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(1, big_num3.GetAsLong())

  def testBigNumSubtractsInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(4).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num1 -= big_num2
    self.assertEqual(1, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())

  def testBigNumOperationsInPlaceRaisesValueErrorOnImmutableBigNums(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    self.assertRaises(ValueError, big_num1.__iadd__, big_num2)

  def testBigNumMultiplies(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num3 = big_num1 * big_num2
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(6, big_num3.GetAsLong())

  def testBigNumMultipliesInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num1 *= big_num2
    self.assertEqual(6, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())

  def testBigNumMods(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(5)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num3 = big_num1 % big_num2
    self.assertEqual(5, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(2, big_num3.GetAsLong())

  def testBigNumModsInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(5).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num1 %= big_num2
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())

  def testBigNumExponentiates(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num3 = big_num1**big_num2
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(8, big_num3.GetAsLong())

  def testBigNumExponentiatesInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    big_num1 **= big_num2
    self.assertEqual(8, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())

  def testBigNumRShifts(self):
    big_num = ssl_util.BigNum.FromLongNumber(4)
    big_num1 = big_num >> 1
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(4, big_num.GetAsLong())

  def testBigNumRShiftsInPlace(self):
    big_num = ssl_util.BigNum.FromLongNumber(4)
    big_num >>= 1
    self.assertEqual(2, big_num.GetAsLong())

  def testBigNumLShifts(self):
    big_num = ssl_util.BigNum.FromLongNumber(4)
    big_num1 = big_num << 1
    self.assertEqual(8, big_num1.GetAsLong())
    self.assertEqual(4, big_num.GetAsLong())

  def testBigNumLShiftsInPlace(self):
    big_num = ssl_util.BigNum.FromLongNumber(4)
    big_num <<= 1
    self.assertEqual(8, big_num.GetAsLong())

  def testBigNumDivides(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(6)
    big_num2 = ssl_util.BigNum.FromLongNumber(2)
    self.assertEqual(3, (big_num1 / big_num2).GetAsLong())
    self.assertEqual(6, big_num1.GetAsLong())
    self.assertEqual(2, big_num2.GetAsLong())

  def testBigNumDividesInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(6)
    big_num2 = ssl_util.BigNum.FromLongNumber(2)
    big_num1 /= big_num2
    self.assertEqual(3, big_num1.GetAsLong())
    self.assertEqual(2, big_num2.GetAsLong())

  def testBigNumDivisionByZeroRaisesAssertionError(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(6)
    big_num2 = ssl_util.BigNum.FromLongNumber(0)
    self.assertRaises(AssertionError, big_num1.__div__, big_num2)

  def testBigNumDivisionRaisesValueErrorWhenThereIsARemainder(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(5)
    big_num2 = ssl_util.BigNum.FromLongNumber(2)
    self.assertRaises(ValueError, big_num1.__div__, big_num2)

  def testBigNumModMultiplies(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    mod_big_num = ssl_util.BigNum.FromLongNumber(5)
    big_num3 = big_num1.ModMul(big_num2, mod_big_num)
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(5, mod_big_num.GetAsLong())
    self.assertEqual(1, big_num3.GetAsLong())

  def testBigNumModMultipliesInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    mod_big_num = ssl_util.BigNum.FromLongNumber(5)
    big_num1.IModMul(big_num2, mod_big_num)
    self.assertEqual(1, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(5, mod_big_num.GetAsLong())

  def testBigNumModExponentiates(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2)
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    mod_big_num = ssl_util.BigNum.FromLongNumber(7)
    big_num3 = big_num1.ModExp(big_num2, mod_big_num)
    self.assertEqual(2, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(7, mod_big_num.GetAsLong())
    self.assertEqual(1, big_num3.GetAsLong())

  def testBigNumModExponentiatesInPlace(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(2).Mutable()
    big_num2 = ssl_util.BigNum.FromLongNumber(3)
    mod_big_num = ssl_util.BigNum.FromLongNumber(7)
    big_num1.IModExp(big_num2, mod_big_num)
    self.assertEqual(1, big_num1.GetAsLong())
    self.assertEqual(3, big_num2.GetAsLong())
    self.assertEqual(7, mod_big_num.GetAsLong())

  def testBigNumGCD(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num2 = ssl_util.BigNum.FromLongNumber(20)
    big_num3 = ssl_util.BigNum.FromLongNumber(15)
    big_num4 = big_num2.GCD(big_num1)
    big_num5 = big_num2.GCD(big_num3)
    self.assertEqual(11, big_num1.GetAsLong())
    self.assertEqual(20, big_num2.GetAsLong())
    self.assertEqual(15, big_num3.GetAsLong())
    self.assertEqual(1, big_num4.GetAsLong())
    self.assertEqual(5, big_num5.GetAsLong())

  def testBigNumModInverse(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num_mod = ssl_util.BigNum.FromLongNumber(20)
    big_num_result = big_num1.ModInverse(big_num_mod)
    self.assertEqual(11, big_num1.GetAsLong())
    self.assertEqual(20, big_num_mod.GetAsLong())
    self.assertEqual(11, big_num_result.GetAsLong())

  def testBigNumModSqrt(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num_mod = ssl_util.BigNum.FromLongNumber(19)
    big_num_result = big_num1.ModSqrt(big_num_mod)
    self.assertEqual(11, big_num1.GetAsLong())
    self.assertEqual(19, big_num_mod.GetAsLong())
    self.assertEqual(7, big_num_result.GetAsLong())

  def testBigNumModInverseInvalidForNotRelativelyPrimes(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(10)
    big_num_mod = ssl_util.BigNum.FromLongNumber(20)
    self.assertRaises(ValueError, big_num1.ModInverse, big_num_mod)
    self.assertEqual(10, big_num1.GetAsLong())
    self.assertEqual(20, big_num_mod.GetAsLong())

  def testBigNumNegates(self):
    big_num = ssl_util.BigNum.FromLongNumber(10)
    big_num = big_num.ModNegate(ssl_util.BigNum.FromLongNumber(6))
    self.assertEqual(2, big_num.GetAsLong())

  def testBigNumAddsOne(self):
    big_num = ssl_util.BigNum.FromLongNumber(10)
    self.assertEqual(11, big_num.AddOne().GetAsLong())

  def testBigNumSubtractOne(self):
    big_num = ssl_util.BigNum.FromLongNumber(10)
    self.assertEqual(9, big_num.SubtractOne().GetAsLong())

  def testBigNumGeneratesRandsBetweenZeroAndGivenBigNum(self):
    big_num = ssl_util.BigNum.FromLongNumber(3)
    big_rand = big_num.GenerateRand()
    self.assertTrue(0 <= big_rand.GetAsLong() < 3)  # pylint: disable=g-generic-assert

  def testBigNumGeneratesZeroForRandWhenTheUpperBoundIsOne(self):
    big_num = ssl_util.BigNum.FromLongNumber(1)
    self._GenericRandomTestForCasesThatShouldReturnOneNum(
        ssl_util.BigNum.Zero(), big_num.GenerateRand
    )

  def testBigNumGeneratesRandsBetweenStartAndGivenBigNum(self):
    big_num = ssl_util.BigNum.FromLongNumber(3)
    big_rand = big_num.GenerateRandWithStart(ssl_util.BigNum.FromLongNumber(1))
    self.assertTrue(1 <= big_rand.GetAsLong() < 3)  # pylint: disable=g-generic-assert

  def testBigNumGeneratesSingleRandWhenIntervalIsOne(self):
    start = ssl_util.BigNum.FromLongNumber(2**30 - 1)
    end = ssl_util.BigNum.FromLongNumber(2**30)
    self._GenericRandomTestForCasesThatShouldReturnOneNum(
        start, end.GenerateRandWithStart, start
    )

  def testBigNumIsBitSet(self):
    big_num = ssl_util.BigNum.FromLongNumber(11)
    self.assertTrue(big_num.IsBitSet(0))
    self.assertTrue(big_num.IsBitSet(1))
    self.assertFalse(big_num.IsBitSet(2))
    self.assertTrue(big_num.IsBitSet(3))

  def testBigNumEq(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num2 = ssl_util.BigNum.FromLongNumber(11)
    self.assertEqual(big_num1, big_num2)

  def testBigNumNeq(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num2 = ssl_util.BigNum.FromLongNumber(12)
    self.assertNotEqual(big_num1, big_num2)

  def testBigNumGt(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num2 = ssl_util.BigNum.FromLongNumber(12)
    self.assertGreater(big_num2, big_num1)

  def testBigNumGtEq(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    big_num2 = ssl_util.BigNum.FromLongNumber(11)
    big_num3 = ssl_util.BigNum.FromLongNumber(12)
    self.assertGreaterEqual(big_num2, big_num1)
    self.assertGreaterEqual(big_num3, big_num2)

  def testBigNumComparisonWithOtherTypesRaisesValueError(self):
    big_num1 = ssl_util.BigNum.FromLongNumber(11)
    self.assertRaises(ValueError, big_num1.__lt__, 11)

  def testClonesCreatesANewBigNum(self):
    big_num = ssl_util.BigNum.FromLongNumber(0).Mutable()
    clone_big_num = big_num.Clone()
    big_num += ssl_util.BigNum.One()
    self.assertEqual(ssl_util.BigNum.Zero(), clone_big_num)
    self.assertEqual(ssl_util.BigNum.One(), big_num)

  def testBigNumCacheIsSingleton(self):
    cache1 = ssl_util.BigNumCache(10)
    cache2 = ssl_util.BigNumCache(11)
    self.assertIs(cache1, cache2)

  def testBigNumCacheReturnsTheSameCachedBigNum(self):
    cache = ssl_util.BigNumCache(10)
    self.assertIs(cache.Get(1), cache.Get(1))

  def testBigNumCacheReturnsDifferentBigNumWhenCacheIsFull(self):
    cache = ssl_util.BigNumCache(10)
    for i in range(10):
      cache.Get(i)
    self.assertIsNot(cache.Get(11), cache.Get(11))

  def testStringRepresentation(self):
    big_num = ssl_util.BigNum.FromLongNumber(11)
    self.assertEqual('11', '{}'.format(big_num))


class _HashMock(object):

  def __init__(self):
    self.with_patch = patch('hashlib.sha512')

  def __enter__(self):
    hashlib_mock = self.with_patch.__enter__()
    sha512_mock = mock.MagicMock()
    hashlib_mock.return_value = sha512_mock
    return sha512_mock, hashlib_mock

  def __exit__(self, t, value, traceback):
    self.with_patch.__exit__(t, value, traceback)


class PRNGTest(unittest.TestCase):

  def testPRNG(self):
    with _HashMock() as (hash_mock, hashlib_mock):
      hash_mock.digest.return_value = b'\x7f' + b'\x01' * 64
      prng = PRNG(b'\x02' * 32)
      self.assertEqual(0, prng.GetRand(2))
      self.assertEqual(1, prng.GetRand(256))
      self.assertEqual(2, prng.GetRand(257))
      self.assertEqual(128, prng.GetRand(32768))
      self.assertEqual(257, prng.GetRand(65536))
      hash_mock.digest.assert_called_once_with()
      hashlib_mock.assert_called_once_with(b'\x00' * 4 + b'\x02' * 32)

  def testGetNBitRandReturnsAtLeastUpperLimit(self):
    with _HashMock() as (hash_mock, hashlib_mock):
      hash_mock.digest.return_value = b'\x81\x82\xff\x05' + b'\x00' * 60
      prng = PRNG(b'\x00' * 32)
      self.assertEqual(5, prng.GetRand(129))
      hash_mock.digest.assert_called_once_with()
      hashlib_mock.assert_called_once_with(b'\x00' * 4 + b'\x00' * 32)

  def testRaisesValueErrorWhenSeedIsNotAtLeastFourBytes(self):
    self.assertRaises(ValueError, PRNG, b'\x00' * 31)

  def testRaisesValueErrorWhenMaxNumberOfHashingIsDone(self):
    prng = PRNG(b'\x00' * 32, 1)
    upper_limit = 1 << 512
    for _ in range(256):
      prng.GetRand(upper_limit)
    self.assertRaises(AssertionError, prng.GetRand, 2)
    self.assertEqual(0, prng.GetRand(1))

  def testGetsMoreBytesWithHashingUntilSufficientBytesArePresent(self):
    with _HashMock() as (hash_mock, _):
      hash_mock.digest.side_effect = [
          b'\x80' + b'\x00' * 63,
          b'\x00' * 64,
          b'\x00' * 64,
      ]
      prng = PRNG(b'\x00' * 32, 1)
      upper_limit = 1 << 1025
      self.assertEqual(1 << 1024, prng.GetRand(upper_limit))
      hash_mock.digest.assert_has_calls([call(), call(), call()])


if __name__ == '__main__':
  unittest.main()
