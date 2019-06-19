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

#include "crypto/elgamal.h"

#include <vector>

#include "glog/logging.h"
#include "crypto/big_num.h"
#include "crypto/ec_group.h"
#include "crypto/ec_point.h"
#include "util/status.inc"
#include "util/status_macros.h"

namespace private_join_and_compute {

namespace elgamal {

util::StatusOr<
    std::pair<std::unique_ptr<PublicKey>, std::unique_ptr<PrivateKey>>>
GenerateKeyPair(const ECGroup& ec_group) {
  ECPoint g = RETURN_OR_ASSIGN(ec_group.GetFixedGenerator());
  BigNum x = ec_group.GeneratePrivateKey();
  ECPoint y = RETURN_OR_ASSIGN(g.Mul(x));

  std::unique_ptr<PublicKey> public_key(
      new PublicKey({std::move(g), std::move(y)}));
  std::unique_ptr<PrivateKey> private_key(new PrivateKey({std::move(x)}));

  return {{std::move(public_key), std::move(private_key)}};
}

util::StatusOr<elgamal::Ciphertext> Mul(
    const elgamal::Ciphertext& ciphertext1,
    const elgamal::Ciphertext& ciphertext2) {
  ECPoint u = RETURN_OR_ASSIGN(ciphertext1.u.Add(ciphertext2.u));
  ECPoint e = RETURN_OR_ASSIGN(ciphertext1.e.Add(ciphertext2.e));
  return {{std::move(u), std::move(e)}};
}

util::StatusOr<elgamal::Ciphertext> Exp(const elgamal::Ciphertext& ciphertext,
                                        const BigNum& scalar) {
  ECPoint u = RETURN_OR_ASSIGN(ciphertext.u.Mul(scalar));
  ECPoint e = RETURN_OR_ASSIGN(ciphertext.e.Mul(scalar));
  return {{std::move(u), std::move(e)}};
}

util::StatusOr<Ciphertext> GetZero(const ECGroup* group) {
  ECPoint u = RETURN_OR_ASSIGN(group->GetPointAtInfinity());
  ECPoint e = RETURN_OR_ASSIGN(group->GetPointAtInfinity());
  return {{std::move(u), std::move(e)}};
}

util::StatusOr<Ciphertext> CloneCiphertext(const Ciphertext& ciphertext) {
  ECPoint clone_u = RETURN_OR_ASSIGN(ciphertext.u.Clone());
  ECPoint clone_e = RETURN_OR_ASSIGN(ciphertext.e.Clone());
  return {{std::move(clone_u), std::move(clone_e)}};
}

bool IsCiphertextZero(const Ciphertext& ciphertext) {
  return ciphertext.u.IsPointAtInfinity() && ciphertext.e.IsPointAtInfinity();
}

}  // namespace elgamal

////////////////////////////////////////////////////////////////////////////////
// PUBLIC ELGAMAL
////////////////////////////////////////////////////////////////////////////////

ElGamalEncrypter::ElGamalEncrypter(
    const ECGroup* ec_group,
    std::unique_ptr<elgamal::PublicKey> elgamal_public_key)
    : ec_group_(ec_group), public_key_(std::move(elgamal_public_key)) {}

// Encrypts a message m, that has already been mapped onto the curve.
util::StatusOr<elgamal::Ciphertext> ElGamalEncrypter::Encrypt(
    const ECPoint& message) const {
  BigNum r = ec_group_->GeneratePrivateKey();  // generate a random exponent
  // u = g^r , e = m * y^r .
  ECPoint u = RETURN_OR_ASSIGN(public_key_->g.Mul(r));
  ECPoint y_to_r = RETURN_OR_ASSIGN(public_key_->y.Mul(r));
  ECPoint e = RETURN_OR_ASSIGN(message.Add(y_to_r));
  return {{std::move(u), std::move(e)}};
}

util::StatusOr<elgamal::Ciphertext> ElGamalEncrypter::ReRandomize(
      const elgamal::Ciphertext& elgamal_ciphertext) const {
  BigNum r = ec_group_->GeneratePrivateKey();  // generate a random exponent
  // u = old_u * g^r , e = old_e * y^r .
  ECPoint g_to_r = RETURN_OR_ASSIGN(public_key_->g.Mul(r));
  ECPoint u = RETURN_OR_ASSIGN(elgamal_ciphertext.u.Add(g_to_r));
  ECPoint y_to_r = RETURN_OR_ASSIGN(public_key_->y.Mul(r));
  ECPoint e = RETURN_OR_ASSIGN(elgamal_ciphertext.e.Add(y_to_r));
  return {{std::move(u), std::move(e)}};
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE ELGAMAL
////////////////////////////////////////////////////////////////////////////////

ElGamalDecrypter::ElGamalDecrypter(
    std::unique_ptr<elgamal::PrivateKey> elgamal_private_key)
    : private_key_(std::move(elgamal_private_key)) {}

util::StatusOr<ECPoint> ElGamalDecrypter::Decrypt(
    const elgamal::Ciphertext& ciphertext) const {
  ECPoint u_to_x = RETURN_OR_ASSIGN(ciphertext.u.Mul(private_key_->x));
  ECPoint u_to_x_inverse = RETURN_OR_ASSIGN(u_to_x.Inverse());
  ECPoint message = RETURN_OR_ASSIGN(ciphertext.e.Add(u_to_x_inverse));
  return {std::move(message)};
}

}  // namespace private_join_and_compute
