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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utility>

#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute::elgamal_proto_util {
namespace {

using ::testing::Test;

const int kTestCurveId = NID_X9_62_prime256v1;

TEST(ElGamalProtoUtilTest, PublicKeyConversion) {
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(auto key_pair, elgamal::GenerateKeyPair(ec_group));
  auto public_key_struct = std::move(key_pair.first);
  ASSERT_OK_AND_ASSIGN(
      auto public_key_proto,
      elgamal_proto_util::SerializePublicKey(*public_key_struct));
  ASSERT_OK_AND_ASSIGN(
      auto public_key_struct_2,
      elgamal_proto_util::DeserializePublicKey(&ec_group, public_key_proto));
  EXPECT_EQ(public_key_struct->g, public_key_struct_2->g);
  EXPECT_EQ(public_key_struct->y, public_key_struct_2->y);
}

TEST(ElGamalProtoUtilTest, PrivateKeyConversion) {
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(auto key_pair, elgamal::GenerateKeyPair(ec_group));
  auto private_key_struct = std::move(key_pair.second);
  ASSERT_OK_AND_ASSIGN(
      auto private_key_proto,
      elgamal_proto_util::SerializePrivateKey(*private_key_struct));
  ASSERT_OK_AND_ASSIGN(
      auto private_key_struct_2,
      elgamal_proto_util::DeserializePrivateKey(&context, private_key_proto));
  EXPECT_EQ(private_key_struct->x, private_key_struct_2->x);
}

TEST(ElGamalProtoUtilTest, CiphertextConversion) {
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(ECPoint u, ec_group.GetRandomGenerator());
  ASSERT_OK_AND_ASSIGN(ECPoint e, ec_group.GetRandomGenerator());
  elgamal::Ciphertext ciphertext_struct{std::move(u), std::move(e)};
  ASSERT_OK_AND_ASSIGN(
      auto ciphertext_proto,
      elgamal_proto_util::SerializeCiphertext(ciphertext_struct));
  ASSERT_OK_AND_ASSIGN(
      auto ciphertext_struct_2,
      elgamal_proto_util::DeserializeCiphertext(&ec_group, ciphertext_proto));
  EXPECT_EQ(ciphertext_struct.u, ciphertext_struct_2.u);
  EXPECT_EQ(ciphertext_struct.e, ciphertext_struct_2.e);
}

}  // namespace
}  // namespace private_join_and_compute::elgamal_proto_util
