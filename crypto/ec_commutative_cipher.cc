/*
 * Copyright 2019 Google Inc.
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

#include "crypto/ec_commutative_cipher.h"

#include <utility>

#include "crypto/elgamal.h"
#include "util/status.inc"
#include "util/status_macros.h"

using ::util::StatusOr;

namespace private_join_and_compute {

using util::StatusOr;

ECCommutativeCipher::ECCommutativeCipher(std::unique_ptr<Context> context,
                                         ECGroup group, BigNum private_key)
    : context_(std::move(context)),
      group_(std::move(group)),
      private_key_(std::move(private_key)),
      private_key_inverse_(private_key_.ModInverse(group_.GetOrder())) {}

util::StatusOr<std::unique_ptr<ECCommutativeCipher>>
ECCommutativeCipher::CreateWithNewKey(int curve_id) {
  std::unique_ptr<Context> context(new Context);
  ECGroup group = RETURN_OR_ASSIGN(ECGroup::Create(curve_id, context.get()));
  BigNum private_key = group.GeneratePrivateKey();
  return std::unique_ptr<ECCommutativeCipher>(new ECCommutativeCipher(
      std::move(context), std::move(group), std::move(private_key)));
}

util::StatusOr<std::unique_ptr<ECCommutativeCipher>>
ECCommutativeCipher::CreateFromKey(int curve_id, const std::string& key_bytes) {
  std::unique_ptr<Context> context(new Context);
  ECGroup group = RETURN_OR_ASSIGN(ECGroup::Create(curve_id, context.get()));
  BigNum private_key = context->CreateBigNum(key_bytes);
  auto status = group.CheckPrivateKey(private_key);
  if (!status.ok()) {
    return status;
  }
  return std::unique_ptr<ECCommutativeCipher>(new ECCommutativeCipher(
      std::move(context), std::move(group), std::move(private_key)));
}

StatusOr<std::string> ECCommutativeCipher::Encrypt(
    const std::string& plaintext) const {
  ECPoint point = RETURN_OR_ASSIGN(group_.GetPointByHashingToCurve(plaintext));
  return RETURN_OR_ASSIGN(Encrypt(point)).ToBytesCompressed();
}

StatusOr<std::string> ECCommutativeCipher::ReEncrypt(
    const std::string& ciphertext) const {
  ECPoint point = RETURN_OR_ASSIGN(group_.CreateECPoint(ciphertext));
  return RETURN_OR_ASSIGN(Encrypt(point)).ToBytesCompressed();
}

StatusOr<ECPoint> ECCommutativeCipher::Encrypt(const ECPoint& point) const {
  return point.Mul(private_key_);
}

util::StatusOr<std::pair<std::string, std::string>>
ECCommutativeCipher::ReEncryptElGamalCiphertext(
    const std::pair<std::string, std::string>& elgamal_ciphertext) const {
  ECPoint u = RETURN_OR_ASSIGN(group_.CreateECPoint(elgamal_ciphertext.first));
  ECPoint e = RETURN_OR_ASSIGN(group_.CreateECPoint(elgamal_ciphertext.second));

  elgamal::Ciphertext decoded_ciphertext = {std::move(u), std::move(e)};

  elgamal::Ciphertext reencrypted_ciphertext =
      RETURN_OR_ASSIGN(elgamal::Exp(decoded_ciphertext, private_key_));

  auto encoded_reencrypted_ciphertext = std::make_pair(
      RETURN_OR_ASSIGN(reencrypted_ciphertext.u.ToBytesCompressed()),
      RETURN_OR_ASSIGN(reencrypted_ciphertext.e.ToBytesCompressed()));

  return encoded_reencrypted_ciphertext;
}

util::StatusOr<std::string> ECCommutativeCipher::Decrypt(
    const std::string& ciphertext) const {
  ECPoint point = RETURN_OR_ASSIGN(group_.CreateECPoint(ciphertext));
  return RETURN_OR_ASSIGN(point.Mul(private_key_inverse_)).ToBytesCompressed();
}

std::string ECCommutativeCipher::GetPrivateKeyBytes() const {
  return private_key_.ToBytes();
}

}  // namespace private_join_and_compute
