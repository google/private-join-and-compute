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

"""Test class for EcCommutativeCipher."""

import unittest
from private_join_and_compute.py.ciphers import ec_cipher
from private_join_and_compute.py.crypto_util import supported_curves
from private_join_and_compute.py.crypto_util import supported_hashes


class EcCommutativeCipherTest(unittest.TestCase):

  def setUp(self):
    super(EcCommutativeCipherTest, self).setUp()
    self.client_cipher = ec_cipher.EcCipher(713)
    self.server_cipher = ec_cipher.EcCipher(713)

  def ReEncryptionSameId(self, cipher1, cipher2):
    user_id = b'3274646578436540569872403985702934875092834502'
    enc_id1 = cipher1.Encrypt(user_id)
    enc_id2 = cipher2.Encrypt(user_id)
    result1 = cipher2.ReEncrypt(enc_id1)
    result2 = cipher1.ReEncrypt(enc_id2)
    self.assertEqual(result1, result2)

  def testReEncryptionSameId(self):
    self.ReEncryptionSameId(self.client_cipher, self.server_cipher)

  def testReEncryptionDifferentId(self):
    user_id1 = b'3274646578436540569872403985702934875092834502'
    user_id2 = b'7402039857096829483572943875209348524958235824'
    enc_id1 = self.client_cipher.Encrypt(user_id1)
    enc_id2 = self.server_cipher.Encrypt(user_id2)
    result1 = self.server_cipher.ReEncrypt(enc_id1)
    result2 = self.client_cipher.ReEncrypt(enc_id2)
    self.assertNotEqual(result1, result2)

  def testDecode(self):
    user_id = b'7402039857096829483572943875209348524958235824'
    enc_id1 = self.client_cipher.Encrypt(user_id)
    enc_id2 = self.server_cipher.Encrypt(user_id)
    result1 = self.server_cipher.ReEncrypt(enc_id1)
    actual_enc_id1 = self.client_cipher.DecryptReEncryptedId(result1)
    actual_enc_id2 = self.server_cipher.DecryptReEncryptedId(result1)
    self.assertEqual(enc_id1, actual_enc_id2)
    self.assertEqual(enc_id2, actual_enc_id1)

  def testDifferentHashFunctions(self):
    # freshly sampled key
    sha256_cipher = ec_cipher.EcCipher(
        curve_id=supported_curves.SupportedCurve.SECP256R1.id,
        hash_type=supported_hashes.HashType.SHA256,
    )
    sha512_cipher = ec_cipher.EcCipher(
        curve_id=supported_curves.SupportedCurve.SECP256R1.id,
        hash_type=supported_hashes.HashType.SHA512,
        private_key_bytes=sha256_cipher.ec_key.priv_key_bytes,
    )
    user_id = b'7402039857096829483572943875209348524958235824'
    enc_id1 = sha256_cipher.Encrypt(user_id)
    enc_id2 = sha512_cipher.Encrypt(user_id)
    self.assertNotEqual(enc_id1, enc_id2)


if __name__ == '__main__':
  unittest.main()
