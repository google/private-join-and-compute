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


"""Test class for Convertors."""

import unittest

from private_join_and_compute.py.crypto_util import converters


class ConvertorsTest(unittest.TestCase):

  def testLongToBytes(self):
    bytes_n = converters.LongToBytes(5)
    self.assertEqual(b'\005', bytes_n)

  def testZeroToBytes(self):
    bytes_n = converters.LongToBytes(0)
    self.assertEqual(b'\000', bytes_n)

  def testLongToBytesForBigNum(self):
    bytes_n = converters.LongToBytes(2**72 - 1)
    self.assertEqual(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff', bytes_n)

  def testBytesToLong(self):
    number = converters.BytesToLong(b'\005')
    self.assertEqual(5, number)

  def testBytesToLongForBigNum(self):
    number = converters.BytesToLong(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    self.assertEqual(2**72 - 1, number)

  def testLongToBytesCompatibleWithBytesToLong(self):
    long_num = 4239423984023840823047823975923401283971204812394723040127401238
    self.assertEqual(
        long_num, converters.BytesToLong(converters.LongToBytes(long_num))
    )

  def testLongToBytesWithPadding(self):
    bytes_n = converters.LongToBytes(5, 6)
    self.assertEqual(b'\000\000\000\000\000\005', bytes_n)

  def testBytesToLongWithPadding(self):
    number = converters.BytesToLong(b'\000\000\000\000\000\005')
    self.assertEqual(5, number)

  def testLongToBytesCompatibleWithBytesToLongWithPadding(self):
    long_num = 4239423984023840823047823975923401283971204812394723040127401238
    self.assertEqual(
        long_num, converters.BytesToLong(converters.LongToBytes(long_num, 51))
    )

  def testLongToBytesRaisesValueErrorForNegativeNumbers(self):
    self.assertRaises(ValueError, converters.LongToBytes, -1)


if __name__ == '__main__':
  unittest.main()
