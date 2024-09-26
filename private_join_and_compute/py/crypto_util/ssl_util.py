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


"""Make available access to openssl library and bn functions."""

import ctypes.util
from functools import total_ordering
import hashlib
import math
from typing import Union

from absl import logging
from private_join_and_compute.py.crypto_util import converters
from private_join_and_compute.py.crypto_util.supported_hashes import HashType
import six

ssl = None

try:
  ssl_libpath = ctypes.util.find_library('crypto')
  ssl = ctypes.cdll.LoadLibrary(ssl_libpath)
except (OSError, IOError) as e:
  logging.fatal('Could not load the ssl library.\n%s', e)

ssl.ERR_error_string_n.restype = ctypes.c_void_p
ssl.ERR_error_string_n.argtypes = [
    ctypes.c_long,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
ssl.ERR_get_error.restype = ctypes.c_long
ssl.ERR_get_error.argtypes = []

ssl.BN_new.restype = ctypes.c_void_p
ssl.BN_new.argtypes = []
ssl.BN_free.argtypes = [ctypes.c_void_p]
ssl.BN_num_bits.restype = ctypes.c_int
ssl.BN_num_bits.argtypes = [ctypes.c_void_p]
ssl.BN_bin2bn.restype = ctypes.c_void_p
ssl.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
ssl.BN_bn2bin.restype = ctypes.c_int
ssl.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_CTX_new.restype = ctypes.c_void_p
ssl.BN_CTX_new.argtypes = []
ssl.BN_CTX_free.restype = ctypes.c_int
ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]
ssl.BN_mod_exp.restype = ctypes.c_int
ssl.BN_mod_exp.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_mod_mul.restype = ctypes.c_int
ssl.BN_mod_mul.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_CTX_new.argtypes = []
ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]
ssl.BN_generate_prime_ex.restype = ctypes.c_int
ssl.BN_generate_prime_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_is_prime_ex.restype = ctypes.c_int
ssl.BN_is_prime_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_mul.restype = ctypes.c_int
ssl.BN_mul.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_div.restype = ctypes.c_int
ssl.BN_div.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_exp.restype = ctypes.c_int
ssl.BN_exp.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.RAND_seed.restype = ctypes.c_int
ssl.RAND_seed.argtypes = [ctypes.c_void_p, ctypes.c_int]
ssl.BN_gcd.restype = ctypes.c_int
ssl.BN_gcd.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_mod_inverse.restype = ctypes.c_void_p
ssl.BN_mod_inverse.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_mod_sqrt.restype = ctypes.c_void_p
ssl.BN_mod_sqrt.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_add.restype = ctypes.c_int
ssl.BN_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_sub.restype = ctypes.c_int
ssl.BN_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_nnmod.restype = ctypes.c_int
ssl.BN_nnmod.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_rand_range.restype = ctypes.c_int
ssl.BN_rand_range.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_lshift.restype = ctypes.c_int
ssl.BN_lshift.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
ssl.BN_rshift.restype = ctypes.c_int
ssl.BN_rshift.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
ssl.BN_cmp.restype = ctypes.c_int
ssl.BN_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_is_bit_set.restype = ctypes.c_int
ssl.BN_is_bit_set.argtypes = [ctypes.c_void_p, ctypes.c_int]

ssl.EVP_PKEY_new.argtypes = []
ssl.EVP_PKEY_new.restype = ctypes.c_void_p

ssl.EC_KEY_new.restype = ctypes.c_void_p
ssl.EC_KEY_new.argtypes = []
ssl.EC_KEY_free.argtypes = [ctypes.c_void_p]
ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]
ssl.EC_KEY_generate_key.restype = ctypes.c_int
ssl.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]
ssl.EC_KEY_set_asn1_flag.restype = None
ssl.EC_KEY_set_asn1_flag.argtypes = [ctypes.c_void_p, ctypes.c_int]

ssl.EC_KEY_get0_public_key.restype = ctypes.c_void_p
ssl.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_set_public_key.restype = ctypes.c_int
ssl.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_KEY_get0_private_key.restype = ctypes.c_void_p
ssl.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_set_private_key.restype = ctypes.c_int
ssl.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_KEY_check_key.restype = ctypes.c_int
ssl.EC_KEY_check_key.argtypes = [ctypes.c_void_p]

ssl.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
ssl.EVP_PKEY_free.restype = None

ssl.EVP_PKEY_get1_EC_KEY.restype = ctypes.c_void_p
ssl.EVP_PKEY_get1_EC_KEY.argtypes = [ctypes.c_void_p]

ssl.EC_GROUP_free.argtypes = [ctypes.c_void_p]
ssl.EC_GROUP_get_order.restype = ctypes.c_int
ssl.EC_GROUP_get_order.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.EC_GROUP_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_GROUP_new_by_curve_name.argtypes = [ctypes.c_int]
ssl.EC_GROUP_get0_generator.restype = ctypes.c_void_p
ssl.EC_GROUP_get0_generator.argtypes = [ctypes.c_void_p]

ssl.EC_POINT_new.argtypes = [ctypes.c_void_p]
ssl.EC_POINT_new.restype = ctypes.c_void_p
ssl.EC_POINT_dup.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.EC_POINT_dup.restype = ctypes.c_void_p

ssl.EC_POINT_free.argtypes = [ctypes.c_void_p]

ssl.EC_POINT_mul.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.EC_POINT_mul.restype = ctypes.c_int

ssl.EC_POINT_add.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.EC_POINT_add.restype = ctypes.c_int

ssl.EC_POINT_point2oct.restype = ctypes.c_int
ssl.EC_POINT_point2oct.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
]
ssl.EC_POINT_oct2point.restype = ctypes.c_int
ssl.EC_POINT_oct2point.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
]

ssl.EC_POINT_is_on_curve.restype = ctypes.c_int
ssl.EC_POINT_is_on_curve.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.EC_POINT_is_at_infinity.restype = ctypes.c_int
ssl.EC_POINT_is_at_infinity.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.EC_POINT_set_to_infinity.restype = ctypes.c_int
ssl.EC_POINT_set_to_infinity.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_POINT_cmp.restype = ctypes.c_int
ssl.EC_POINT_cmp.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

ssl.PEM_write_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.PEM_write_PUBKEY.restypes = ctypes.c_int

ssl.PEM_write_PrivateKey.restype = ctypes.c_int
ssl.PEM_write_PrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.PEM_read_PrivateKey.restype = ctypes.c_void_p
ssl.PEM_read_PrivateKey.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

ssl.EVP_PKEY_set1_EC_KEY.restype = ctypes.c_int
ssl.EVP_PKEY_set1_EC_KEY.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_GROUP_get_curve_GFp.restype = ctypes.c_int
ssl.EC_GROUP_get_curve_GFp.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

ssl.EC_POINT_set_affine_coordinates_GFp.restype = ctypes.c_int
ssl.EC_POINT_set_affine_coordinates_GFp.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

ssl.BN_MONT_CTX_new.restype = ctypes.c_void_p
ssl.BN_MONT_CTX_new.argtypes = []
ssl.BN_MONT_CTX_set.restype = ctypes.c_int
ssl.BN_MONT_CTX_set.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_MONT_CTX_free.argtypes = [ctypes.c_void_p]
ssl.BN_mod_mul_montgomery.restype = ctypes.c_int
ssl.BN_mod_mul_montgomery.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_to_montgomery.restype = ctypes.c_int
ssl.BN_to_montgomery.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_from_montgomery.restype = ctypes.c_int
ssl.BN_from_montgomery.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ssl.BN_copy.restype = ctypes.c_void_p
ssl.BN_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
ssl.BN_dup.restype = ctypes.c_void_p
ssl.BN_dup.argtypes = [ctypes.c_void_p]

pointer = ctypes.pointer
cast = ctypes.cast


class SSLProxy(object):
  """Wrapper (a pass-through with error checking) for the loaded ssl library.

  This class checks the ssl methods returning pointers does not return None and
  also checks methods returning 0 on failure. In case of a failure, it prints
  OpenSSL error messages.
  """

  def __init__(self, ssl_lib):
    self._ssl = ssl_lib
    self._cache = {}
    # Functions without a return value or having a return value that is already
    # explicitly checked in the code.
    self._funcs_to_skip = {
        'BN_free',
        'BN_CTX_free',
        'BN_cmp',
        'BN_num_bits',
        'BN_bn2bin',
        'EC_POINT_is_at_infinity',
        'EC_POINT_cmp',
        'EC_POINT_free',
        'EC_KEY_free',
        'BN_MONT_CTX_free',
        'BN_is_bit_set',
        'EC_GROUP_free',
        'BN_is_prime_ex',
        'EC_POINT_point2oct',
    }

  def _DebugInfo(self):
    """Returns the last error message from the OpenSSL library."""
    err = ctypes.create_string_buffer(256)
    self._ssl.ERR_error_string_n(self._ssl.ERR_get_error(), err, 256)
    return '\nOpenSSL Error: {}'.format(err.value)

  def __getattr__(self, name):
    if name in self._funcs_to_skip:
      return getattr(self._ssl, name)
    if name not in self._cache:

      def WrapperFunc(*args):
        func = getattr(self._ssl, name)
        ret = func(*args)
        if func.restype is ctypes.c_void_p:
          assert ret is not None, 'ret is None{}'.format(self._DebugInfo())
        elif func.restype is ctypes.c_int:
          assert 1 == ret, 'ret is not 1, ret: {}{}'.format(
              ret, self._DebugInfo()
          )
        return ret

      self._cache[name] = WrapperFunc
    return self._cache[name]


ssl = SSLProxy(ssl)


def LongtoBn(bn_r: int, a: int) -> int:
  """Converts a to BigNum and stores in preallocated bn_r."""
  bytes_a = converters.LongToBytes(a)
  return ssl.BN_bin2bn(bytes_a, len(bytes_a), bn_r)


def BnToLong(bn_a: int) -> int:
  """Converts BigNum to long."""
  num_bits_in_a = ssl.BN_num_bits(bn_a)
  num_bytes_in_a = int(math.ceil(num_bits_in_a / 8.0))
  bytes_a = ctypes.create_string_buffer(num_bytes_in_a)
  ssl.BN_bn2bin(bn_a, bytes_a)
  return converters.BytesToLong(bytes_a.raw)


def BnToBytes(bn_a: int) -> bytes:
  """Converts BigNum to long."""
  num_bits_in_a = ssl.BN_num_bits(bn_a)
  num_bytes_in_a = int(math.ceil(num_bits_in_a / 8.0))
  bytes_a = ctypes.create_string_buffer(num_bytes_in_a)
  ssl.BN_bn2bin(bn_a, bytes_a)
  return bytes_a.raw


def BytesToBn(bytes_a: bytes) -> int:
  """Converts BigNum to long."""
  bn_r = ssl.BN_new()
  ssl.BN_bin2bn(bytes_a, len(bytes_a), bn_r)
  return bn_r


def GetRandomInRange(long_start: int, long_end: int) -> int:
  """ "Returns a random in the range [long_start, long_end)."""
  with TempBNs(rand=None, interval=(long_end - long_start)) as bn:
    ssl.BN_rand_range(bn.rand, bn.interval)
    return BnToLong(bn.rand) + long_start


def ModExp(g: int, x: int, n: int) -> int:
  """Computes g^x mod n."""
  with TempBNs(r=None, g=g, x=x, n=n) as bn:
    ssl.BN_mod_exp(bn.r, bn.g, bn.x, bn.n, OpenSSLHelper().ctx)
    return BnToLong(bn.r)


def ModInverse(x: int, n: int) -> int:
  """Computes 1/x mod n."""
  with TempBNs(r=None, x=x, n=n) as bn:
    ssl.BN_mod_inverse(bn.r, bn.x, bn.n, OpenSSLHelper().ctx)
    return BnToLong(bn.r)


class TempBNs(object):
  """Class for creating temporary openssl bignums by using 'with' clause."""

  # Disable pytype attribute checking.
  _HAS_DYNAMIC_ATTRIBUTES = True

  def __init__(self, **kwargs):
    r"""Initializes and assigns all temporary bignums.

    Usage:
      with TempBNs(x=5, y=[10,11]) as bn:
        # bn.x is the temporary bignum holding the value 5 within this scope.
        # bn.y is the temporary list of bignum holding the value 10 and 11
        # within this scope.

    or it can be used for assigning temporary results into bignums as follows:
      with TempBNs(result=None, x=5) as bn:
        # bn.result is an empty temporary bignum within this scope.
        # bn.x is the same as before.

    or bytes can be given as well as longs:
      with TempBNs(x=5, y=['\001', '\002']) as bn:
        # bn.x is the temporary bignum holding the value 5 within this scope.
        # bn.y is the temporary list of bignum holding the value 1 and 2 within
        # this scope.

    Args:
      **kwargs: key (variable), value (int or long) pairs.
    """
    self._args = []
    for key, value in kwargs.items():
      assert not hasattr(self, key), '{} already exists.'.format(key)
      if isinstance(value, list):
        assert value, 'Cannot declare empty list in TempBNs.'
        for v in value:
          self._args.append(ssl.BN_new())
          self._BytesOrLongToBn(self._args[-1], v)
        setattr(self, key, self._args[-len(value) :])
      else:
        self._args.append(ssl.BN_new())
        setattr(self, key, self._args[-1])
        if value:
          self._BytesOrLongToBn(self._args[-1], value)

  @classmethod
  def _BytesOrLongToBn(cls, bn, val) -> int:
    if isinstance(val, int):
      LongtoBn(bn, val)
    if isinstance(val, str):
      ssl.BN_bin2bn(val, len(val), bn)

  def __enter__(self, *args):
    return self

  def __exit__(self, some_type, value, traceback):
    for bn in self._args:
      ssl.BN_free(bn)


def RandomOracle(
    x: Union[int, bytes],
    max_value: int,
    hash_type: Union[type(None), HashType] = None,
) -> int:
  """A random oracle function mapping x deterministically into a large domain.

  The random oracle is similar to the example given in the last paragraph of
  Chapter 6 of [1] where the output is expanded by successively hashing the
  concatenation of the input with a fixed sized counter starting from 1.

  [1] Bellare, Mihir, and Phillip Rogaway. "Random oracles are practical:
  A paradigm for designing efficient protocols." Proceedings of the 1st ACM
  conference on Computer and communications security. ACM, 1993.

  Args:
    x: long or string input
    max_value: the max value of the output domain.
    hash_type: the hash function to use, as a HashType. If 'None' is provided
      this defaults to HashType.SHA512.

  Returns:
    a long value from the set [0, max_value).

  Raises:
    ValueError: if bit length of max_value is greater than
      hash_type.bit_length * 254. Since the counter used for expanding the
      output is expanded to 8 bit length (hard-coded), any counter value that is
      greater than 256 would cause variable length inputs passed to the
      underlying hash calls and might make this random oracle's output not
      uniform across the output domain. The output length is increased by a
      security value of hash_type.bit_length which reduces the bias of selecting
      certain values more often than others when max_value is not a multiple of
      2.
  """
  if hash_type is None:
    hash_type = HashType.SHA512
  output_bit_length = max_value.bit_length() + hash_type.bit_length
  iter_count = int(math.ceil(float(output_bit_length) / hash_type.bit_length))
  if iter_count > 255:
    raise ValueError(
        'The domain bit length must not be greater than H * 254. '
        'Given bit length: {}'.format(output_bit_length)
    )
  excess_bit_count = (iter_count * hash_type.bit_length) - output_bit_length
  hash_output = 0
  bytes_x = x if isinstance(x, bytes) else converters.LongToBytes(x)
  for i in range(1, iter_count + 1):
    hash_output <<= hash_type.bit_length
    hash_output |= hash_type.hash(
        six.ensure_binary(converters.LongToBytes(i) + bytes_x)
    )
  return (hash_output >> excess_bit_count) % max_value


class PRNG(object):
  """Hash based counter mode pseudorandom number generator.

  The technique used in this class is same as the one used in RandomOracle
  function.
  """

  def __init__(self, seed, counter_byte_len=4):
    """Creates the PRNG with the given seed.

    Args:
      seed: at least 32 byte number or string.
      counter_byte_len: the max number of counter bytes to use. After exceeding
        the counter, this PRNG should not be used.

    Raises:
      ValueError: when the seed is not at least 32 bytes.
    """
    self.seed = (
        seed if isinstance(seed, bytes) else converters.LongToBytes(seed)
    )
    if len(self.seed) < 32:
      raise ValueError(
          'seed needs to be at least 32 bytes, the given bytes: {}'.format(
              self.seed
          )
      )
    self.cur_pad = 0
    self.cur_bytes = b''
    self.cur_byte_len = counter_byte_len
    self.limit = 1 << (self.cur_byte_len * 8)

  def _GetMore(self):
    assert self.cur_pad < self.limit, 'Limit has been reached.'
    hash_output = six.ensure_binary(
        hashlib.sha512(
            six.ensure_binary(self._PaddedCountBytes() + self.seed)
        ).digest()
    )
    self.cur_pad += 1
    self.cur_bytes += hash_output

  def _PaddedCountBytes(self):
    counter_bytes = converters.LongToBytes(self.cur_pad)
    # Although we could use {:\x004}.format, Python seems to print space when
    # doing this way for the null character.
    return b'\000' * (self.cur_byte_len - len(counter_bytes)) + counter_bytes

  def _GetNBitRand(self, n):
    """Gets a random number in [0, 2^n) interval."""
    byte_len = (n + 7) >> 3
    excess_len = (8 - (n % 8)) % 8
    while len(self.cur_bytes) < byte_len:
      self._GetMore()
    self.cur_bytes, rand = (
        self.cur_bytes[byte_len:],
        self.cur_bytes[:byte_len],
    )
    rand_num = converters.BytesToLong(rand) >> excess_len
    return rand_num

  def GetRand(self, upper_limit):
    """Gets a random number in [0, upper_limit) interval."""
    bit_len = (upper_limit - 1).bit_length()
    rand_num = self._GetNBitRand(bit_len)
    while rand_num >= upper_limit:
      rand_num = self._GetNBitRand(bit_len)
    return rand_num


class OpenSSLHelper(object):
  """A singleton wrapper class for openssl ctx and seeding its rand.

  Context is used for caching already allocated big nums. Each openssl operation
  requires a context to be passed to Get temporary big nums avoiding allocating
  new big nums for these temporary nums thus making big num operations use
  memory resources more efficiently. Usage in openssl library:

  BN_CTX_start(ctx)
  ....
  temp = BN_CTX_get(ctx)
  ....
  BN_CTX_end(ctx)
  Please note that BN_CTX_start and BN_CTX_end is not implemented here as this
  is only passed to various openssl big num operations.
  """

  _instance = None

  def __new__(cls, *args, **kwargs):
    if not cls._instance:
      cls._instance = super(OpenSSLHelper, cls).__new__(cls, *args, **kwargs)
    return cls._instance

  def __init__(self):
    self._ctx = ssl.BN_CTX_new()
    # So that garbage collection doesn't collect ssl before this object.
    self.ssl = ssl

  def __del__(self):
    # clean up
    self.ssl.BN_CTX_free(self._ctx)

  @property
  def ctx(self):
    return self._ctx


@total_ordering
class BigNum(object):
  """A wrapper class for openssl bn numbers.

  Used for arithmetic operations on long numbers.
  """

  _ZERO = None
  _ONE = None
  _TWO = None

  def __init__(self, bn_num):
    self._bn_num = bn_num
    self._helper = OpenSSLHelper()
    self.immutable = True
    # So that garbage collection doesn't collect ssl before this object.
    self.ssl = ssl

  @classmethod
  def Zero(cls):
    if not cls._ZERO:
      cls._ZERO = cls.FromLongNumber(0)
    return cls._ZERO

  @classmethod
  def One(cls):
    if not cls._ONE:
      cls._ONE = cls.FromLongNumber(1)
    return cls._ONE

  @classmethod
  def Two(cls):
    if not cls._TWO:
      cls._TWO = cls.FromLongNumber(2)
    return cls._TWO

  @classmethod
  def FromLongNumber(cls, long_number: int) -> 'BigNum':
    """Returns a BigNum constructed from the given long number."""
    bytes_num = converters.LongToBytes(long_number)
    return cls.FromBytes(bytes_num)

  @classmethod
  def FromBytes(cls, number_in_bytes):
    """Returns a BigNum constructed from the given long number."""
    bn_num = ssl.BN_new()
    ssl.BN_bin2bn(number_in_bytes, len(number_in_bytes), bn_num)
    return BigNum(bn_num)

  @classmethod
  def GenerateSafePrime(cls, prime_length):
    """Returns a safe prime BigNum with the given bit-length."""
    bn_prime_num = ssl.BN_new()
    ssl.BN_generate_prime_ex(bn_prime_num, prime_length, 1, None, None, None)
    return BigNum(bn_prime_num)

  @classmethod
  def GeneratePrime(cls, prime_length: int) -> 'BigNum':
    """Returns a prime BigNum with the given bit-length."""
    bn_prime_num = ssl.BN_new()
    ssl.BN_generate_prime_ex(bn_prime_num, prime_length, 0, None, None, None)
    return BigNum(bn_prime_num)

  def GeneratePrimeForSubGroup(self, prime_length: int) -> 'BigNum':
    """Returns a prime BigNum, p, satisfying p = (self * k) + 1 for some k.

    Args:
      prime_length: the bit length of the returned prime.

    Returns:
      a prime BigNum, p = (self * k) + 1 for some k.
    """
    bn_prime_num = ssl.BN_new()
    ssl.BN_generate_prime_ex(
        bn_prime_num, prime_length, 0, self._bn_num, None, None
    )
    return BigNum(bn_prime_num)

  def IsPrime(self, error_probability=1e-6):
    """Returns True if this big num is prime, False otherwise."""
    rounds = int(math.ceil(-math.log(error_probability) / math.log(4)))
    return ssl.BN_is_prime_ex(self._bn_num, rounds, self._helper.ctx, None) != 0

  def IsSafePrime(self, error_probability=1e-6):
    """Returns True if this big num is a safe prime, False otherwise."""
    return self.IsPrime(error_probability) and (
        (self - self.One()) / self.Two()
    ).IsPrime(error_probability)

  def IsBitSet(self, n):
    """Returns True if the n-th bit is set, False otherwise."""
    return ssl.BN_is_bit_set(self._bn_num, n)

  def BitLength(self):
    return ssl.BN_num_bits(self._bn_num)

  def Clone(self):
    """Clones this big num."""
    return BigNum(ssl.BN_dup(self._bn_num))

  def Mutable(self):
    """Sets this BigNum to mutable so that it can be changed."""
    self.immutable = False
    return self

  def __hash__(self):
    return hash((self._bn_num, self.immutable))

  def __del__(self):
    self.ssl.BN_free(self._bn_num)

  def __add__(self, other):
    return self._ComputeResult(ssl.BN_add, None, other)

  def __iadd__(self, other):
    return self._ComputeResultInPlace(ssl.BN_add, None, other)

  def __sub__(self, other):
    return self._ComputeResult(ssl.BN_sub, None, other)

  def __isub__(self, other):
    return self._ComputeResultInPlace(ssl.BN_sub, None, other)

  def __mul__(self, other):
    return self._ComputeResult(ssl.BN_mul, self._helper.ctx, other)

  def __imul__(self, other):
    return self._ComputeResultInPlace(ssl.BN_mul, self._helper.ctx, other)

  def __mod__(self, modulus):
    return self._ComputeResult(ssl.BN_nnmod, self._helper.ctx, modulus)

  def __imod__(self, modulus):
    return self._ComputeResultInPlace(ssl.BN_nnmod, self._helper.ctx, modulus)

  def __pow__(self, other):
    return self._ComputeResult(ssl.BN_exp, self._helper.ctx, other)

  def __ipow__(self, other):
    return self._ComputeResultInPlace(ssl.BN_exp, self._helper.ctx, other)

  def __rshift__(self, n):
    bn_num = ssl.BN_new()
    ssl.BN_rshift(bn_num, self._bn_num, n)
    return BigNum(bn_num)

  def __irshift__(self, n):
    ssl.BN_rshift(self._bn_num, self._bn_num, n)
    return self

  def __lshift__(self, n):
    bn_num = ssl.BN_new()
    ssl.BN_lshift(bn_num, self._bn_num, n)
    return BigNum(bn_num)

  def __ilshift__(self, n):
    ssl.BN_lshift(self._bn_num, self._bn_num, n)
    return self

  def __div__(self, other):
    return self._Div(BigNum(ssl.BN_new()), self, other)

  def __truediv__(self, other):
    return self._Div(BigNum(ssl.BN_new()), self, other)

  def __idiv__(self, other):
    return self._Div(self, self, other)

  def _Div(self, big_result, big_num, other_big_num):
    """Divides two bignums.

    Args:
      big_result: The bignum where the result is stored.
      big_num:  The numerator.
      other_big_num:  The denominator.

    Returns:
      big_result.

    Raises:
      ValueError:  If the remainder is non-zero.
    """
    if isinstance(other_big_num, self.__class__):
      bn_remainder = ssl.BN_new()
      ssl.BN_div(
          big_result._bn_num,
          bn_remainder,
          big_num._bn_num,
          other_big_num._bn_num,
          self._helper.ctx,
      )
      try:
        if ssl.BN_cmp(bn_remainder, self.Zero()._bn_num) != 0:
          raise ValueError(
              'There is a remainder in division of {} and {}'.format(
                  big_num.GetAsLong(), other_big_num.GetAsLong()
              )
          )
        return big_result
      finally:
        ssl.BN_free(bn_remainder)

  def ModMul(self, other, modulus):
    """Modular multiplies this with other based on the modulus.

    For efficiency, please use Montgomery multiplication module if this is done
    multiple times with the same modulus.

    Args:
      other: the other BigNum
      modulus: the modulus of the operation

    Returns:
      a new BigNum holding the result.
    """
    return self._ComputeResult(ssl.BN_mod_mul, self._helper.ctx, other, modulus)

  def IModMul(self, other, modulus):
    """Modular multiplies this with other based on the modulus.

    Stores the result in this BigNum.
    For efficiency, please use Montgomery multiplication module if this is done
    multiple times with the same modulus.

    Args:
      other: the other BigNum
      modulus: the modulus of the operation

    Returns:
      self
    """
    return self._ComputeResultInPlace(
        ssl.BN_mod_mul, self._helper.ctx, other, modulus
    )

  def ModExp(self, other, modulus):
    """Modular exponentiates this with other based on the modulus.

    Args:
      other: the other BigNum
      modulus: the modulus of the operation

    Returns:
      a new BigNum holding the result.
    """
    return self._ComputeResult(ssl.BN_mod_exp, self._helper.ctx, other, modulus)

  def IModExp(self, other, modulus):
    """Modular exponentiates this with other based on the modulus.

    Args:
      other: the other BigNum
      modulus: the modulus of the operation

    Returns:
      self
    """
    return self._ComputeResultInPlace(
        ssl.BN_mod_exp, self._helper.ctx, other, modulus
    )

  def GCD(self, other):
    """Gets gcd as a BigNum."""
    return self._ComputeResult(ssl.BN_gcd, self._helper.ctx, other)

  def ModInverse(self, modulus):
    """Gets the inverse of this BigNum in mod modulus."""
    try:
      return self._ComputeResult(ssl.BN_mod_inverse, self._helper.ctx, modulus)
    except AssertionError as a:
      raise ValueError(
          'This big num {} and modulus {} are not relatively '
          'primes.\nThe Assertion Error: {}'.format(
              self.GetAsLong(), modulus.GetAsLong(), a
          )
      )

  def ModSqrt(self, modulus):
    """Gets the sqrt of this BigNum in mod modulus.

    Args:
      modulus: the modulus of the operation

    Returns:
      a new BigNum holding the result.
    """
    big_num_result = self._ComputeResult(
        ssl.BN_mod_sqrt, self._helper.ctx, modulus
    )
    return big_num_result

  def IModSqrt(self, modulus):
    """Gets the sqrt of this BigNum in mod modulus.

    Args:
      modulus: the modulus of the operation

    Returns:
      self
    """
    return self._ComputeResultInPlace(
        ssl.BN_mod_sqrt, self._helper.ctx, modulus
    )

  def GenerateRand(self):
    """Generates a cryptographically strong pseudo-random between 0 & self.

    Returns:
      A BigNum in [0, self._big_num) range.
    """
    bn_rand = ssl.BN_new()
    ssl.BN_rand_range(bn_rand, self._bn_num)
    return BigNum(bn_rand)

  def GenerateRandWithStart(self, start_big_num):
    """Generates a cryptographically strong pseudo-random between start & self.

    Args:
      start_big_num: start BigNum value of the interval.

    Returns:
      A BigNum in [start, self._big_num) range.
    """
    return (self - start_big_num).GenerateRand() + start_big_num

  def ModNegate(self, modulus):
    return modulus - (self % modulus)

  def AddOne(self):
    return self + self.One()

  def SubtractOne(self):
    return self - self.One()

  def __str__(self):
    return str(self.GetAsLong())

  def __eq__(self, other):
    # pylint: disable=protected-access
    if isinstance(other, self.__class__):
      return ssl.BN_cmp(self._bn_num, other._bn_num) == 0
    raise ValueError('Cannot compare BigNum with type {}'.format(type(other)))
    # pylint: enable=protected-access

  def __ne__(self, other):
    return not self == other

  def __lt__(self, other):
    # pylint: disable=protected-access
    if isinstance(other, self.__class__):
      return ssl.BN_cmp(self._bn_num, other._bn_num) == -1
    raise ValueError('Cannot compare BigNum with type {}'.format(type(other)))
    # pylint: enable=protected-access

  def _ComputeResult(self, func, ctx, *args):
    return self._ComputeResultIntoBigNum(
        BigNum(ssl.BN_new()), func, ctx, self, *args
    )

  def _ComputeResultInPlace(self, func, ctx, *args):
    if self.immutable:
      raise ValueError(
          'This operation will change this immutable BigNum. Call '
          'Mutable method to change it.'
      )
    return self._ComputeResultIntoBigNum(self, func, ctx, self, *args)

  @classmethod
  def _ComputeResultIntoBigNum(cls, big_num_result, func, ctx, *args):
    # pylint: disable=protected-access
    if all(isinstance(big_num, cls) for big_num in args):
      args = [big_num._bn_num for big_num in args]
      if ctx:
        args.append(ctx)
      func(big_num_result._bn_num, *args)
      return big_num_result
    return NotImplemented
    # pylint: enable=protected-access

  def GetAsLong(self):
    """Gets the long number in this BigNum."""
    return converters.BytesToLong(self.GetAsBytes())

  def GetAsBytes(self):
    """Gets the long number as bytes in this BigNum."""
    num_bits = ssl.BN_num_bits(self._bn_num)
    num_bytes = int(math.ceil(num_bits / 8.0))
    bytes_num = ctypes.create_string_buffer(num_bytes)
    ssl.BN_bn2bin(self._bn_num, bytes_num)
    return bytes_num.raw


class BigNumCache(object):
  """A singleton cache holding BigNum representations of small numbers."""

  _instance = None

  def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
    if not cls._instance:
      cls._instance = super(BigNumCache, cls).__new__(cls)
    return cls._instance

  def __init__(self, max_count: int):
    self._cache = {}
    self._max_count = max_count

  def Get(self, num: int) -> BigNum:
    """Gets the BigNum from the cache or creates a new BigNum.

    If max_count is reached, a new BigNum is created and returned without
    storing in the cache.
    Args:
      num: the long or integer to convert to BigNum.

    Returns:
      a BigNum for the given num.
    """
    if num not in self._cache:
      if len(self._cache) >= self._max_count:
        return BigNum.FromLongNumber(num)
      self._cache[num] = BigNum.FromLongNumber(num)
    return self._cache[num]
