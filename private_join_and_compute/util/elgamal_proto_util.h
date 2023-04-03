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

// Helper functions that enable conversion between ElGamal structs and protocol
// buffer messsages.

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_ELGAMAL_PROTO_UTIL_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_ELGAMAL_PROTO_UTIL_H_

#include <memory>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"

namespace private_join_and_compute::elgamal_proto_util {

// Converts a struct elgamal::PublicKey into a protocol buffer
// ::private_join_and_compute::ElGamalPublicKey.
StatusOr<ElGamalPublicKey> SerializePublicKey(
    const elgamal::PublicKey& public_key_struct);

// Converts a protocol buffer ElGamalPublicKey into a struct
// elgamal::PublicKey. ec_group is used for ECPoint operations.
StatusOr<std::unique_ptr<elgamal::PublicKey>> DeserializePublicKey(
    const ECGroup* ec_group, const ElGamalPublicKey& public_key_proto);

// Converts a struct elgamal::PrivateKey into a protocol buffer
// ::private_join_and_compute::ElGamalSecretKey.
StatusOr<::private_join_and_compute::ElGamalSecretKey> SerializePrivateKey(
    const elgamal::PrivateKey& private_key_struct);

// Converts a protocol buffer ::private_join_and_compute::ElGamalSecretKey into
// a struct elgamal::PrivateKey. context is used for BigNum operations.
StatusOr<std::unique_ptr<elgamal::PrivateKey>> DeserializePrivateKey(
    Context* context,
    const ::private_join_and_compute::ElGamalSecretKey& private_key_proto);

// Converts a struct elgamal::Ciphertext into a protocol buffer
// ::private_join_and_compute::ElGamalCiphertext.
StatusOr<ElGamalCiphertext> SerializeCiphertext(
    const elgamal::Ciphertext& ciphertext_struct);

// Converts a protocol buffer ElGamalCiphertext into a struct
// elgamal::Ciphertext. ec_group is used for ECPoint operations.
StatusOr<elgamal::Ciphertext> DeserializeCiphertext(
    const ECGroup* ec_group, const ElGamalCiphertext& ciphertext_proto);

}  // namespace private_join_and_compute::elgamal_proto_util

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_ELGAMAL_PROTO_UTIL_H_
