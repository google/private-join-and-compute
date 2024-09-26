/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVATE_JOIN_AND_COMPUTE_COMMUTATIVE_ELGAMAL_H_
#define PRIVATE_JOIN_AND_COMPUTE_COMMUTATIVE_ELGAMAL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/util/status.inc"

// Defines functions to generate ElGamal public/private keys, and
// to encrypt/decrypt messages using those keys.
// The ciphertexts thus produced are "commutative" with ec_commutative_cipher.
// That is, one can perform an ElGamal encryption, followed by an EC encryption,
// followed by decryptions in any order. Note that we only support one level of
// ElGamal encryption (and any number of levels of EC encryption.)
//
// This class is NOT thread-safe.
//
// Example: To generate a with new public/private ElGamal key pair for the named
// curve NID_X9_62_prime256v1. The key can be securely stored and reused.
//    #include <openssl/obj_mac.h>
//    std::unique_ptr<CommutativeElGamal> elgamal =
//       CommutativeElGamal::CreateWithNewKeyPair(NID_X9_62_prime256v1).value();
//    StatusOr<stringpair> public_key_bytes = elgamal->GetPublicKeyBytes();
//    StatusOr<string> private_key_bytes = elgamal->GetPrivateKeyBytes();
//
//  Example: To generate a cipher with an existing public/private key pair for
//  the named curve NID_X9_62_prime256v1.
//    #include <openssl/obj_mac.h>
//    StatusOr<std::unique_ptr<CommutativeElGamal>> elgamal =
//        CommutativeElGamal::CreateFromPublicAndPrivateKeys(NID_X9_62_prime256v1,
//        public_key_bytes, private_key_bytes);
//
//  Example: To generate a cipher with an existing public key _only_ for
//  the named curve NID_X9_62_prime256v1. The resulting object can only encrypt,
//  not decrypt.
//    #include <openssl/obj_mac.h>
//    StatusOr<std::unique_ptr<CommutativeElGamal>> elgamal =
//        CommutativeElGamal::CreateFromPublicKey(NID_X9_62_prime256v1,
//        public_key_bytes);
//
// Example: To encrypt a message using a std::unique_ptr<ECCommutativeCipher>
//    cipher generated as above. Note that the secret must already mapped to the
//    curve before encrypting it.
//    #include <openssl/obj_mac.h>
//    Context context;
//    EcPointUtil ec_point_util =
//        ECPointUtil::Create(NID_X9_62_prime256v1).value();
//    string point =
//        ec_point_util->HashToCurve("secret").value();
//    StatusOr<stringpair> encrypted_point = elgamal->Encrypt(point);
//
// Example: To decrypt a message that has been encrypted using the same ElGamal
//    key. This does not reverse hashing to the curve.
//
//    StatusOr<string> decrypted_point =
//        cipher->Decrypt(encrypted_point);

namespace private_join_and_compute {

class CommutativeElGamal {
 public:
  // CommutativeElGamal is neither copyable nor assignable.
  CommutativeElGamal(const CommutativeElGamal&) = delete;
  CommutativeElGamal& operator=(const CommutativeElGamal&) = delete;

  ~CommutativeElGamal() = default;

  // Creates a new CommutativeElGamal object by generating a new public/private
  // key pair.
  // Returns INVALID_ARGUMENT status instead if the curve_id is not valid
  // or INTERNAL status when crypto operations are not successful.
  static StatusOr<std::unique_ptr<CommutativeElGamal>> CreateWithNewKeyPair(
      int curve_id);

  // Creates a new CommutativeElGamal object using the given public key.
  // The resulting object will not be able to decrypt ciphertexts, since it
  // doesn't have the private key. However, it can still create encryptions.
  // Returns INVALID_ARGUMENT status instead if the public_key is not valid for
  // the given curve or the curve_id is not valid.
  // Returns INTERNAL status when crypto operations are not successful.
  static StatusOr<std::unique_ptr<CommutativeElGamal>> CreateFromPublicKey(
      int curve_id,
      const std::pair<std::string, std::string>& public_key_bytes);

  // Creates a new CommutativeElGamal object using the given public and private
  // keys. The resulting object will be able to both encrypt and decrypt.
  // Returns INVALID_ARGUMENT status instead if either key is not valid for
  // the given curve, the keys are inconsistent, or the curve_id is not valid.
  // Returns INTERNAL status when crypto operations are not successful.
  static StatusOr<std::unique_ptr<CommutativeElGamal>>
  CreateFromPublicAndPrivateKeys(
      int curve_id, const std::pair<std::string, std::string>& public_key_bytes,
      absl::string_view private_key_bytes);

  // Encrypts the supplied point, and returns the resulting ElGamal ciphertext.
  // Returns INVALID_ARGUMENT if the input is not on the same curve.
  // Returns INTERNAL when crypto operations fail.
  StatusOr<std::pair<std::string, std::string>> Encrypt(
      absl::string_view plaintext) const;

  // Encrypts the identity element of the EC group (typically the point at
  // infinity).  Note that the ciphertext returned by this method will never
  // decrypt successfully; however, it can be used in homomorphic operations,
  // though doing so is equivalent to rerandomizing the ciphertext.
  StatusOr<std::pair<std::string, std::string>> EncryptIdentityElement() const;

  // Decrypts the supplied ElGamal ciphertext, and returns the underlying
  // EC point.
  // Returns INVALID_ARGUMENT if the input ciphertext is not on the same curve,
  // or if this object does not have the ElGamal private key.
  // Returns INTERNAL when crypto operations fail.
  // A special point to note is that the decryption fails if the message
  // decrypts to the point at infinity. This is because the point at infinity
  // does not have a valid serialization in OpenSSL.
  StatusOr<std::string> Decrypt(
      const std::pair<std::string, std::string>& ciphertext) const;

  // Returns a byte representation of the public key.
  // Return INTERNAL error if converting the public key to bytes fails.
  StatusOr<std::pair<std::string, std::string>> GetPublicKeyBytes() const;

  // Returns a byte representation of the private key.
  // Return INVALID_ARGUMENT if the object doesn't have the private key.
  StatusOr<std::string> GetPrivateKeyBytes() const;

 private:
  CommutativeElGamal(std::unique_ptr<Context> ctx, ECGroup group,
                     std::unique_ptr<elgamal::PublicKey> elgamal_public_key,
                     std::unique_ptr<elgamal::PrivateKey> elgamal_private_key);

  CommutativeElGamal(std::unique_ptr<Context> ctx, ECGroup group,
                     std::unique_ptr<elgamal::PublicKey> elgamal_public_key);

  // Context used for storing temporary values to be reused across openssl
  // function calls for better performance.
  std::unique_ptr<Context> context_;

  // The EC Group representing the curve definition.
  const ECGroup group_;

  std::unique_ptr<ElGamalEncrypter> encrypter_;
  std::unique_ptr<ElGamalDecrypter> decrypter_;
};

}  // namespace private_join_and_compute
#endif  // PRIVATE_JOIN_AND_COMPUTE_COMMUTATIVE_ELGAMAL_H_
