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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.pb.h"
#include "private_join_and_compute/util/elgamal_proto_util.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/recordio.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute::elgamal_key_util {
namespace {
using private_join_and_compute::OkStatus;
using private_join_and_compute::ProtoUtils;
}  // namespace

Status GenerateElGamalKeyPair(int curve_id, absl::string_view pub_key_filename,
                              absl::string_view prv_key_filename) {
  Context context;
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, &context));
  ASSIGN_OR_RETURN(auto key_pair,
                   private_join_and_compute::elgamal::GenerateKeyPair(group));
  ASSIGN_OR_RETURN(
      auto public_key_proto,
      elgamal_proto_util::SerializePublicKey(*key_pair.first.get()));
  ASSIGN_OR_RETURN(
      auto private_key_proto,
      elgamal_proto_util::SerializePrivateKey(*key_pair.second.get()));
  RETURN_IF_ERROR(
      ProtoUtils::WriteProtoToFile(public_key_proto, pub_key_filename));
  RETURN_IF_ERROR(
      ProtoUtils::WriteProtoToFile(private_key_proto, prv_key_filename));
  return OkStatus();
}

Status ComputeJointElGamalPublicKey(
    int curve_id, const std::vector<std::string>& shares_filenames,
    absl::string_view join_pub_key_key_filename) {
  if (shares_filenames.empty()) {
    return InvalidArgumentError(
        "elgmal_key_util::ComputeJointElGamalPublicKey() : empty shares files "
        "provided");
  }
  Context context;
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, &context));
  std::vector<std::unique_ptr<elgamal::PublicKey>> shares;
  for (const auto& share_file : shares_filenames) {
    ASSIGN_OR_RETURN(
        auto key_share_proto,
        ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(share_file));
    ASSIGN_OR_RETURN(auto key_share, elgamal_proto_util::DeserializePublicKey(
                                         &group, key_share_proto));
    shares.push_back(std::move(key_share));
  }
  ASSIGN_OR_RETURN(
      auto joint_key,
      private_join_and_compute::elgamal::GeneratePublicKeyFromShares(shares));
  ASSIGN_OR_RETURN(auto joint_key_proto,
                   elgamal_proto_util::SerializePublicKey(*joint_key.get()));
  RETURN_IF_ERROR(
      ProtoUtils::WriteProtoToFile(joint_key_proto, join_pub_key_key_filename));
  return OkStatus();
}
}  // namespace private_join_and_compute::elgamal_key_util
