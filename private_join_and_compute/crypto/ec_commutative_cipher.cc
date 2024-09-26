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

#include "private_join_and_compute/crypto/ec_commutative_cipher.h"

#include <memory>
#include <string>
#include <utility>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

namespace {

constexpr absl::string_view kEcCommutativeCipherDst = "ECCommutativeCipher";

// Invert private scalar using Fermat's Little Theorem to avoid side-channel
// attacks. This avoids the caveat of ModInverseBlinded, namely that the
// underlying BN_mod_inverse_blinded is not available on all platforms.
BigNum InvertPrivateScalar(const BigNum& scalar, const ECGroup& ec_group,
                           Context& context) {
  const BigNum& order = ec_group.GetOrder();
  return scalar.ModExp(order.Sub(context.Two()), order);
}

}  // namespace

ECCommutativeCipher::ECCommutativeCipher(std::unique_ptr<Context> context,
                                         ECGroup group, BigNum private_key,
                                         HashType hash_type)
    : context_(std::move(context)),
      group_(std::move(group)),
      private_key_(std::move(private_key)),
      private_key_inverse_(
          InvertPrivateScalar(private_key_, group_, *context_)),
      hash_type_(hash_type) {}

bool ECCommutativeCipher::ValidateHashType(HashType hash_type) {
  return (hash_type == SHA256 || hash_type == SHA384 || hash_type == SHA512 ||
          hash_type == SSWU_RO);
}

bool ECCommutativeCipher::ValidateHashType(int hash_type) {
  return hash_type >= SHA256 && hash_type <= SSWU_RO;
}

StatusOr<std::unique_ptr<ECCommutativeCipher>>
ECCommutativeCipher::CreateWithNewKey(int curve_id, HashType hash_type) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));
  if (!ECCommutativeCipher::ValidateHashType(hash_type)) {
    return InvalidArgumentError("Invalid hash type.");
  }
  BigNum private_key = group.GeneratePrivateKey();
  return std::unique_ptr<ECCommutativeCipher>(new ECCommutativeCipher(
      std::move(context), std::move(group), std::move(private_key), hash_type));
}

StatusOr<std::unique_ptr<ECCommutativeCipher>>
ECCommutativeCipher::CreateFromKey(int curve_id, absl::string_view key_bytes,
                                   HashType hash_type) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));
  if (!ECCommutativeCipher::ValidateHashType(hash_type)) {
    return InvalidArgumentError("Invalid hash type.");
  }
  BigNum private_key = context->CreateBigNum(key_bytes);
  auto status = group.CheckPrivateKey(private_key);
  if (!status.ok()) {
    return status;
  }
  return std::unique_ptr<ECCommutativeCipher>(new ECCommutativeCipher(
      std::move(context), std::move(group), std::move(private_key), hash_type));
}

StatusOr<std::unique_ptr<ECCommutativeCipher>>
ECCommutativeCipher::CreateWithKeyFromSeed(int curve_id,
                                           absl::string_view seed_bytes,
                                           absl::string_view tag_bytes,
                                           HashType hash_type) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));
  if (seed_bytes.size() < 16) {
    return InvalidArgumentError("Seed is too short.");
  }
  if (!ECCommutativeCipher::ValidateHashType(hash_type)) {
    return InvalidArgumentError("Invalid hash type.");
  }
  BigNum private_key = context->PRF(seed_bytes, tag_bytes, group.GetOrder());
  return std::unique_ptr<ECCommutativeCipher>(new ECCommutativeCipher(
      std::move(context), std::move(group), std::move(private_key), hash_type));
}

StatusOr<std::string> ECCommutativeCipher::Encrypt(
    absl::string_view plaintext) {
  ASSIGN_OR_RETURN(ECPoint hashed_point, HashToTheCurveInternal(plaintext));
  ASSIGN_OR_RETURN(ECPoint encrypted_point, Encrypt(hashed_point));
  return encrypted_point.ToBytesCompressed();
}

StatusOr<std::string> ECCommutativeCipher::ReEncrypt(
    absl::string_view ciphertext) {
  ASSIGN_OR_RETURN(ECPoint point, group_.CreateECPoint(ciphertext));
  ASSIGN_OR_RETURN(ECPoint reencrypted_point, Encrypt(point));
  return reencrypted_point.ToBytesCompressed();
}

StatusOr<ECPoint> ECCommutativeCipher::Encrypt(const ECPoint& point) {
  return point.Mul(private_key_);
}

StatusOr<std::pair<std::string, std::string>>
ECCommutativeCipher::ReEncryptElGamalCiphertext(
    const std::pair<std::string, std::string>& elgamal_ciphertext) {
  ASSIGN_OR_RETURN(ECPoint u, group_.CreateECPoint(elgamal_ciphertext.first));
  ASSIGN_OR_RETURN(ECPoint e, group_.CreateECPoint(elgamal_ciphertext.second));

  elgamal::Ciphertext decoded_ciphertext = {std::move(u), std::move(e)};

  ASSIGN_OR_RETURN(elgamal::Ciphertext reencrypted_ciphertext,
                   elgamal::Exp(decoded_ciphertext, private_key_));

  ASSIGN_OR_RETURN(std::string serialized_u,
                   reencrypted_ciphertext.u.ToBytesCompressed());
  ASSIGN_OR_RETURN(std::string serialized_e,
                   reencrypted_ciphertext.e.ToBytesCompressed());

  return std::make_pair(std::move(serialized_u), std::move(serialized_e));
}

StatusOr<std::string> ECCommutativeCipher::Decrypt(
    absl::string_view ciphertext) {
  ASSIGN_OR_RETURN(ECPoint point, group_.CreateECPoint(ciphertext));
  ASSIGN_OR_RETURN(ECPoint decrypted_point, point.Mul(private_key_inverse_));
  return decrypted_point.ToBytesCompressed();
}

::private_join_and_compute::StatusOr<ECPoint>
ECCommutativeCipher::HashToTheCurveInternal(absl::string_view plaintext) {
  StatusOr<ECPoint> status_or_point;
  if (hash_type_ == SHA512) {
    status_or_point = group_.GetPointByHashingToCurveSha512(plaintext);
  } else if (hash_type_ == SHA384) {
    status_or_point = group_.GetPointByHashingToCurveSha384(plaintext);
  } else if (hash_type_ == SHA256) {
    status_or_point = group_.GetPointByHashingToCurveSha256(plaintext);
  } else if (hash_type_ == SSWU_RO) {
    status_or_point = group_.GetPointByHashingToCurveSswuRo(
        plaintext, kEcCommutativeCipherDst);
  } else {
    return InvalidArgumentError("Invalid hash type.");
  }
  return status_or_point;
}

::private_join_and_compute::StatusOr<std::string>
ECCommutativeCipher::HashToTheCurve(absl::string_view plaintext) {
  ASSIGN_OR_RETURN(ECPoint point, HashToTheCurveInternal(plaintext));
  return point.ToBytesCompressed();
}

std::string ECCommutativeCipher::GetPrivateKeyBytes() const {
  return private_key_.ToBytes();
}

}  // namespace private_join_and_compute
