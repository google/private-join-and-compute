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

#include "private_join_and_compute/util/elgamal_key_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/elgamal.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "private_join_and_compute/crypto/openssl.inc"
#include "private_join_and_compute/util/elgamal_proto_util.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute::elgamal_key_util {
namespace {

using elgamal::PublicKey;
using elgamal_proto_util::DeserializePrivateKey;
using elgamal_proto_util::DeserializePublicKey;
using private_join_and_compute::ElGamalPublicKey;
using private_join_and_compute::ElGamalSecretKey;
using private_join_and_compute::ProtoUtils;
using ::testing::HasSubstr;
using ::testing::Test;

const int kTestCurveId = NID_X9_62_prime256v1;

TEST(ElGamalKeyUtilTest, GenerateKeyPair) {
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string pub_key_filename = (temp_dir / "elgamal_pub.key").string();
  std::string prv_key_filename = (temp_dir / "elgamal_prv.key").string();
  ASSERT_OK(
      GenerateElGamalKeyPair(kTestCurveId, pub_key_filename, prv_key_filename));
  ASSERT_TRUE(std::filesystem::exists(pub_key_filename));
  ASSERT_TRUE(std::filesystem::exists(prv_key_filename));

  // Verify the keys written to files are correct.
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(
      auto public_key_proto,
      ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(pub_key_filename));
  ASSERT_OK_AND_ASSIGN(
      auto private_key_proto,
      ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(prv_key_filename));
  ASSERT_OK_AND_ASSIGN(auto public_key,
                       DeserializePublicKey(&ec_group, public_key_proto));
  ASSERT_OK_AND_ASSIGN(auto private_key,
                       DeserializePrivateKey(&context, private_key_proto));
  ASSERT_OK_AND_ASSIGN(auto product, public_key->g.Mul(private_key->x));
  EXPECT_EQ(product, public_key->y);
}

TEST(ElGamalKeyUtilTest, ComputeJointElGamalPublicKey) {
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string pub_key_filename_1 = (temp_dir / "elgamal_pub1.key").string();
  std::string prv_key_filename_1 = (temp_dir / "elgamal_prv1.key").string();
  ASSERT_OK(GenerateElGamalKeyPair(kTestCurveId, pub_key_filename_1,
                                   prv_key_filename_1));
  std::string pub_key_filename_2 = (temp_dir / "elgamal_pub2.key").string();
  std::string prv_key_filename_2 = (temp_dir / "elgamal_prv2.key").string();
  ASSERT_OK(GenerateElGamalKeyPair(kTestCurveId, pub_key_filename_2,
                                   prv_key_filename_2));
  std::string joint_pub_key_filename =
      (temp_dir / "joint_elgamal_pub.key").string();
  std::vector<std::string> pub_key_shares{pub_key_filename_1,
                                          pub_key_filename_2};
  ASSERT_OK(ComputeJointElGamalPublicKey(kTestCurveId, pub_key_shares,
                                         joint_pub_key_filename));
  ASSERT_TRUE(std::filesystem::exists(joint_pub_key_filename));

  // Verify the joint key written to file is correct.
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(
      auto joint_public_key_proto,
      ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(joint_pub_key_filename));
  ASSERT_OK_AND_ASSIGN(auto joint_public_key,
                       DeserializePublicKey(&ec_group, joint_public_key_proto));
  ASSERT_OK_AND_ASSIGN(
      auto share_1_proto,
      ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(pub_key_filename_1));
  ASSERT_OK_AND_ASSIGN(auto share_1,
                       DeserializePublicKey(&ec_group, share_1_proto));
  ASSERT_OK_AND_ASSIGN(
      auto share_2_proto,
      ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(pub_key_filename_2));
  ASSERT_OK_AND_ASSIGN(auto share_2,
                       DeserializePublicKey(&ec_group, share_2_proto));
  std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
  key_shares.reserve(2);
  key_shares.push_back(std::move(share_1));
  key_shares.push_back(std::move(share_2));
  ASSERT_OK_AND_ASSIGN(auto expected_joint_public_key,
                       elgamal::GeneratePublicKeyFromShares(key_shares));
  EXPECT_EQ(joint_public_key->g, expected_joint_public_key->g);
  EXPECT_EQ(joint_public_key->y, expected_joint_public_key->y);
}

TEST(ElGamalKeyUtilTest, TestEmptyKeyShares) {
  std::vector<std::string> empty_key_shares;
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string joint_pub_key_filename =
      (temp_dir / "joint_elgamal_pub.key").string();
  auto outcome = ComputeJointElGamalPublicKey(kTestCurveId, empty_key_shares,
                                              joint_pub_key_filename);
  EXPECT_TRUE(IsInvalidArgument(outcome));
}

TEST(ElGamalKeyUtilTest, TestKeyReadWrite) {
  std::unique_ptr<Context> context(new Context);
  ASSERT_OK_AND_ASSIGN(ECGroup group,
                       ECGroup::Create(kTestCurveId, context.get()));
  ASSERT_OK_AND_ASSIGN(
      auto key_pair, private_join_and_compute::elgamal::GenerateKeyPair(group));
  ASSERT_OK_AND_ASSIGN(
      auto public_key_proto,
      elgamal_proto_util::SerializePublicKey(*key_pair.first.get()));
  ASSERT_OK_AND_ASSIGN(
      auto private_key_proto,
      elgamal_proto_util::SerializePrivateKey(*key_pair.second.get()));

  std::filesystem::path temp_dir(::testing::TempDir());
  std::string pub_key_filename = (temp_dir / "elgamal_pub.key").string();
  std::string prv_key_filename = (temp_dir / "elgamal_prv.key").string();

  // Verify write and read public key to file returns the expected key.
  ASSERT_OK(ProtoUtils::WriteProtoToFile(public_key_proto, pub_key_filename));
  ASSERT_OK_AND_ASSIGN(
      auto public_key_proto_2,
      ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(pub_key_filename));
  EXPECT_EQ(public_key_proto.g(), public_key_proto_2.g());
  EXPECT_EQ(public_key_proto.y(), public_key_proto_2.y());

  // Verify write and read private key to file returns the expected key.
  ASSERT_OK(ProtoUtils::WriteProtoToFile(private_key_proto, prv_key_filename));
  ASSERT_OK_AND_ASSIGN(
      auto private_key_proto_2,
      ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(prv_key_filename));
  EXPECT_EQ(private_key_proto.x(), private_key_proto_2.x());
}

}  // namespace
}  // namespace private_join_and_compute::elgamal_key_util
