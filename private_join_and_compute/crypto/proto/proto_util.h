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

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PROTO_PROTO_UTIL_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PROTO_PROTO_UTIL_H_

#include <string>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "src/google/protobuf/message.h"

namespace private_join_and_compute {
// Converts a std::vector<BigNum> into a protocol buffer BigNumVector.
proto::BigNumVector BigNumVectorToProto(
    absl::Span<const BigNum> big_num_vector);

// Converts a protocol buffer BigNumVector into a std::vector<BigNum>.
std::vector<BigNum> ParseBigNumVectorProto(
    Context* context, const proto::BigNumVector& big_num_vector_proto);

// Converts a std::vector<ECPoint> into a protocol buffer ECPointVector.
StatusOr<proto::ECPointVector> ECPointVectorToProto(
    absl::Span<const ECPoint> ec_point_vector);

// Converts a protocol buffer ECPointVector into a std::vector<ECPoint>.
StatusOr<std::vector<ECPoint>> ParseECPointVectorProto(
    Context* context, ECGroup* ec_group,
    const proto::ECPointVector& ec_point_vector_proto);

// Serializes a proto to a string by serializing the fields in tag order. This
// will guarantee deterministic encoding, as long as there are no cross-language
// strings, and no unknown fields across different serializations.
std::string SerializeAsStringInOrder(const google::protobuf::Message& proto);

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PROTO_PROTO_UTIL_H_
