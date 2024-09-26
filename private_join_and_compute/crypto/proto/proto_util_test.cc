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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/openssl.inc"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace {

const int kTestCurveId = NID_secp384r1;

TEST(ProtoUtilTest, ToBigNumVectorAndBack) {
  Context ctx;
  std::vector<BigNum> big_num_vector = {ctx.One(), ctx.Two(), ctx.Three()};

  proto::BigNumVector big_num_vector_proto =
      BigNumVectorToProto(big_num_vector);
  std::vector<BigNum> deserialized =
      ParseBigNumVectorProto(&ctx, big_num_vector_proto);

  EXPECT_EQ(big_num_vector, deserialized);
}

TEST(ProtoUtilTest, ParseEmptyBigNumVector) {
  Context ctx;
  std::vector<BigNum> empty_big_num_vector = {};
  proto::BigNumVector big_num_vector_proto;  // Default instance.
  std::vector<BigNum> deserialized =
      ParseBigNumVectorProto(&ctx, big_num_vector_proto);

  EXPECT_EQ(empty_big_num_vector, deserialized);
}

TEST(ProtoUtilTest, ToECPointVectorAndBack) {
  Context ctx;
  ASSERT_OK_AND_ASSIGN(ECGroup ec_group, ECGroup::Create(kTestCurveId, &ctx));
  std::vector<ECPoint> ec_point_vector;
  ec_point_vector.reserve(3);
  for (int i = 0; i < 3; ++i) {
    ASSERT_OK_AND_ASSIGN(ECPoint point, ec_group.GetPointByHashingToCurveSha256(
                                            absl::StrCat("point_", i)));
    ec_point_vector.emplace_back(std::move(point));
  }

  ASSERT_OK_AND_ASSIGN(proto::ECPointVector ec_point_vector_proto,
                       ECPointVectorToProto(ec_point_vector));
  ASSERT_OK_AND_ASSIGN(
      std::vector<ECPoint> deserialized,
      ParseECPointVectorProto(&ctx, &ec_group, ec_point_vector_proto));

  EXPECT_EQ(ec_point_vector, deserialized);
}

TEST(ProtoUtilTest, ParseEmptyECPointVector) {
  Context ctx;
  ASSERT_OK_AND_ASSIGN(ECGroup ec_group, ECGroup::Create(kTestCurveId, &ctx));
  std::vector<ECPoint> empty_ec_point_vector = {};
  proto::ECPointVector ec_point_vector_proto;  // Default instance.
  ASSERT_OK_AND_ASSIGN(
      std::vector<ECPoint> deserialized,
      ParseECPointVectorProto(&ctx, &ec_group, ec_point_vector_proto));

  EXPECT_EQ(empty_ec_point_vector, deserialized);
}

TEST(ProtoUtilTest, SerializeAsStringInOrderIsConsistent) {
  Context ctx;
  std::vector<BigNum> big_num_vector = {ctx.One(), ctx.Two(), ctx.Three()};

  proto::PedersenParameters pedersen_parameters_proto;
  pedersen_parameters_proto.set_n(ctx.CreateBigNum(37).ToBytes());
  *pedersen_parameters_proto.mutable_gs() = BigNumVectorToProto(big_num_vector);
  pedersen_parameters_proto.set_h(ctx.CreateBigNum(4).ToBytes());

  const std::string kExpectedSerialized =
      "\n\x1%\x12\t\n\x1\x1\n\x1\x2\n\x1\x3\x1A\x1\x4";
  std::string serialized = SerializeAsStringInOrder(pedersen_parameters_proto);

  EXPECT_EQ(serialized, kExpectedSerialized);
}

}  // namespace
}  // namespace private_join_and_compute
