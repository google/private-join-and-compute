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

#include "private_join_and_compute/crypto/commutative_elgamal.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

CommutativeElGamal::CommutativeElGamal(
    std::unique_ptr<Context> ctx, ECGroup group,
    std::unique_ptr<elgamal::PublicKey> elgamal_public_key,
    std::unique_ptr<elgamal::PrivateKey> elgamal_private_key)
    : context_(std::move(ctx)),
      group_(std::move(group)),
      encrypter_(new ElGamalEncrypter(&group_, std::move(elgamal_public_key))),
      decrypter_(new ElGamalDecrypter(std::move(elgamal_private_key))) {}

CommutativeElGamal::CommutativeElGamal(
    std::unique_ptr<Context> ctx, ECGroup group,
    std::unique_ptr<elgamal::PublicKey> elgamal_public_key)
    : context_(std::move(ctx)),
      group_(std::move(group)),
      encrypter_(new ElGamalEncrypter(&group_, std::move(elgamal_public_key))),
      decrypter_(nullptr) {}

StatusOr<std::unique_ptr<CommutativeElGamal>>
CommutativeElGamal::CreateWithNewKeyPair(int curve_id) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));
  ASSIGN_OR_RETURN(auto key_pair, elgamal::GenerateKeyPair(group));
  std::unique_ptr<CommutativeElGamal> result(new CommutativeElGamal(
      std::move(context), std::move(group), std::move(key_pair.first),
      std::move(key_pair.second)));
  return {std::move(result)};
}

StatusOr<std::unique_ptr<CommutativeElGamal>>
CommutativeElGamal::CreateFromPublicKey(
    int curve_id, const std::pair<std::string, std::string>& public_key_bytes) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));

  ASSIGN_OR_RETURN(ECPoint g, group.CreateECPoint(public_key_bytes.first));
  ASSIGN_OR_RETURN(ECPoint y, group.CreateECPoint(public_key_bytes.second));

  std::unique_ptr<elgamal::PublicKey> public_key(
      new elgamal::PublicKey({std::move(g), std::move(y)}));
  std::unique_ptr<CommutativeElGamal> result(new CommutativeElGamal(
      std::move(context), std::move(group), std::move(public_key)));
  return {std::move(result)};
}

StatusOr<std::unique_ptr<CommutativeElGamal>>
CommutativeElGamal::CreateFromPublicAndPrivateKeys(
    int curve_id, const std::pair<std::string, std::string>& public_key_bytes,
    absl::string_view private_key_bytes) {
  std::unique_ptr<Context> context(new Context);
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));

  ASSIGN_OR_RETURN(ECPoint g, group.CreateECPoint(public_key_bytes.first));
  ASSIGN_OR_RETURN(ECPoint y, group.CreateECPoint(public_key_bytes.second));

  BigNum x = context->CreateBigNum(private_key_bytes);

  ASSIGN_OR_RETURN(ECPoint expected_y, g.Mul(x));

  if (y != expected_y) {
    return InvalidArgumentError(
        "CommutativeElGamal::CreateFromPublicAndPrivateKeys : Public key is "
        "not consistent with private key");
  }

  std::unique_ptr<elgamal::PublicKey> public_key(
      new elgamal::PublicKey({std::move(g), std::move(y)}));
  std::unique_ptr<elgamal::PrivateKey> private_key(
      new elgamal::PrivateKey({std::move(x)}));
  std::unique_ptr<CommutativeElGamal> result(
      new CommutativeElGamal(std::move(context), std::move(group),
                             std::move(public_key), std::move(private_key)));
  return {std::move(result)};
}

StatusOr<std::pair<std::string, std::string>> CommutativeElGamal::Encrypt(
    absl::string_view plaintext) const {
  ASSIGN_OR_RETURN(ECPoint plaintext_point, group_.CreateECPoint(plaintext));

  ASSIGN_OR_RETURN(elgamal::Ciphertext ciphertext,
                   encrypter_->Encrypt(plaintext_point));

  ASSIGN_OR_RETURN(std::string u_string, ciphertext.u.ToBytesCompressed());
  ASSIGN_OR_RETURN(std::string e_string, ciphertext.e.ToBytesCompressed());

  return {std::make_pair(std::move(u_string), std::move(e_string))};
}

StatusOr<std::pair<std::string, std::string>>
CommutativeElGamal::EncryptIdentityElement() const {
  ASSIGN_OR_RETURN(ECPoint plaintext_point, group_.GetPointAtInfinity());

  ASSIGN_OR_RETURN(elgamal::Ciphertext ciphertext,
                   encrypter_->Encrypt(plaintext_point));

  ASSIGN_OR_RETURN(std::string u_string, ciphertext.u.ToBytesCompressed());
  ASSIGN_OR_RETURN(std::string e_string, ciphertext.e.ToBytesCompressed());

  return {std::make_pair(std::move(u_string), std::move(e_string))};
}

StatusOr<std::string> CommutativeElGamal::Decrypt(
    const std::pair<std::string, std::string>& ciphertext) const {
  if (nullptr == decrypter_) {
    return InvalidArgumentError(
        "CommutativeElGamal::Decrypt: cannot decrypt without the private key.");
  }

  ASSIGN_OR_RETURN(ECPoint u_point, group_.CreateECPoint(ciphertext.first));
  ASSIGN_OR_RETURN(ECPoint e_point, group_.CreateECPoint(ciphertext.second));
  elgamal::Ciphertext decoded_ciphertext(
      {std::move(u_point), std::move(e_point)});

  ASSIGN_OR_RETURN(ECPoint plaintext_point,
                   decrypter_->Decrypt(decoded_ciphertext));

  ASSIGN_OR_RETURN(std::string plaintext, plaintext_point.ToBytesCompressed());

  return {std::move(plaintext)};
}

StatusOr<std::pair<std::string, std::string>>
CommutativeElGamal::GetPublicKeyBytes() const {
  const elgamal::PublicKey* public_key = encrypter_->getPublicKey();
  ASSIGN_OR_RETURN(std::string g_string, public_key->g.ToBytesCompressed());
  ASSIGN_OR_RETURN(std::string y_string, public_key->y.ToBytesCompressed());

  return {std::make_pair(std::move(g_string), std::move(y_string))};
}

StatusOr<std::string> CommutativeElGamal::GetPrivateKeyBytes() const {
  if (nullptr == decrypter_) {
    return InvalidArgumentError(
        "CommutativeElGamal::GetPrivateKeyBytes: private key is not known.");
  }
  return {decrypter_->getPrivateKey()->x.ToBytes()};
}

}  // namespace private_join_and_compute
