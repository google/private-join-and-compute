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

#include "private_join_and_compute/util/elgamal_proto_util.h"

#include <memory>
#include <utility>

namespace private_join_and_compute::elgamal_proto_util {

StatusOr<ElGamalPublicKey> SerializePublicKey(
    const elgamal::PublicKey& public_key_struct) {
  ElGamalPublicKey public_key_proto;
  ASSIGN_OR_RETURN(auto serialized_g, public_key_struct.g.ToBytesCompressed());
  public_key_proto.set_g(serialized_g);
  ASSIGN_OR_RETURN(auto serialized_y, public_key_struct.y.ToBytesCompressed());
  public_key_proto.set_y(serialized_y);
  return public_key_proto;
}

StatusOr<ElGamalCiphertext> SerializeCiphertext(
    const elgamal::Ciphertext& ciphertext_struct) {
  ElGamalCiphertext ciphertext_proto;
  ASSIGN_OR_RETURN(auto serialized_u, ciphertext_struct.u.ToBytesCompressed());
  ciphertext_proto.set_u(serialized_u);
  ASSIGN_OR_RETURN(auto serialized_e, ciphertext_struct.e.ToBytesCompressed());
  ciphertext_proto.set_e(serialized_e);
  return ciphertext_proto;
}

StatusOr<ElGamalSecretKey> SerializePrivateKey(
    const elgamal::PrivateKey& private_key_struct) {
  ElGamalSecretKey private_key_proto;
  private_key_proto.set_x(private_key_struct.x.ToBytes());
  return private_key_proto;
}

StatusOr<std::unique_ptr<elgamal::PublicKey>> DeserializePublicKey(
    const ECGroup* ec_group, const ElGamalPublicKey& public_key_proto) {
  ASSIGN_OR_RETURN(ECPoint public_key_struct_g,
                   ec_group->CreateECPoint(public_key_proto.g()));
  ASSIGN_OR_RETURN(ECPoint public_key_struct_y,
                   ec_group->CreateECPoint(public_key_proto.y()));
  return absl::WrapUnique(new elgamal::PublicKey(
      {std::move(public_key_struct_g), std::move(public_key_struct_y)}));
}

StatusOr<std::unique_ptr<elgamal::PrivateKey>> DeserializePrivateKey(
    Context* context, const ElGamalSecretKey& private_key_proto) {
  BigNum x = context->CreateBigNum(private_key_proto.x());
  return absl::WrapUnique(new elgamal::PrivateKey({std::move(x)}));
}

StatusOr<elgamal::Ciphertext> DeserializeCiphertext(
    const ECGroup* ec_group, const ElGamalCiphertext& ciphertext_proto) {
  ASSIGN_OR_RETURN(ECPoint ciphertext_struct_u,
                   ec_group->CreateECPoint(ciphertext_proto.u()));
  ASSIGN_OR_RETURN(ECPoint ciphertext_struct_e,
                   ec_group->CreateECPoint(ciphertext_proto.e()));
  return elgamal::Ciphertext{std::move(ciphertext_struct_u),
                             std::move(ciphertext_struct_e)};
}

}  // namespace private_join_and_compute::elgamal_proto_util
