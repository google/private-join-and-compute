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

#include "private_join_and_compute/crypto/proto/proto_util.h"

#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

proto::BigNumVector BigNumVectorToProto(
    absl::Span<const BigNum> big_num_vector) {
  proto::BigNumVector big_num_vector_proto;
  big_num_vector_proto.mutable_serialized_big_nums()->Reserve(
      big_num_vector.size());
  for (const auto& bn : big_num_vector) {
    big_num_vector_proto.add_serialized_big_nums(bn.ToBytes());
  }
  return big_num_vector_proto;
}

std::vector<BigNum> ParseBigNumVectorProto(
    Context* context, const proto::BigNumVector& big_num_vector_proto) {
  std::vector<BigNum> big_num_vector;
  for (const auto& serialized_big_num :
       big_num_vector_proto.serialized_big_nums()) {
    big_num_vector.push_back(context->CreateBigNum(serialized_big_num));
  }
  return big_num_vector;
}

// Converts a std::vector<BigNum> into a protocol buffer BigNumVector.
StatusOr<proto::ECPointVector> ECPointVectorToProto(
    absl::Span<const ECPoint> ec_point_vector) {
  proto::ECPointVector ec_point_vector_proto;
  ec_point_vector_proto.mutable_serialized_ec_points()->Reserve(
      ec_point_vector.size());
  for (const auto& ec_point : ec_point_vector) {
    ASSIGN_OR_RETURN(std::string serialized_ec_point,
                     ec_point.ToBytesCompressed());
    ec_point_vector_proto.add_serialized_ec_points(serialized_ec_point);
  }
  return std::move(ec_point_vector_proto);
}

// Converts a protocol buffer BigNumVector into a std::vector<BigNum>.
StatusOr<std::vector<ECPoint>> ParseECPointVectorProto(
    Context* context, ECGroup* ec_group,
    const proto::ECPointVector& ec_point_vector_proto) {
  std::vector<ECPoint> ec_point_vector;
  for (const auto& serialized_ec_point :
       ec_point_vector_proto.serialized_ec_points()) {
    ASSIGN_OR_RETURN(ECPoint ec_point,
                     ec_group->CreateECPoint(serialized_ec_point));
    ec_point_vector.push_back(std::move(ec_point));
  }
  return std::move(ec_point_vector);
}

std::string SerializeAsStringInOrder(const google::protobuf::Message& proto) {
  return proto.SerializeAsString();
}

}  // namespace private_join_and_compute
