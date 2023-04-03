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

#include "private_join_and_compute/crypto/ec_point_util.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

ECPointUtil::ECPointUtil(std::unique_ptr<Context> context, ECGroup group)
    : context_(std::move(context)), group_(std::move(group)) {}

StatusOr<std::unique_ptr<ECPointUtil>> ECPointUtil::Create(int curve_id) {
  std::unique_ptr<Context> context(new Context());
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, context.get()));
  return std::unique_ptr<ECPointUtil>(
      new ECPointUtil(std::move(context), std::move(group)));
}

StatusOr<std::string> ECPointUtil::GetRandomCurvePoint() {
  ASSIGN_OR_RETURN(ECPoint point, group_.GetRandomGenerator());
  return point.ToBytesCompressed();
}

StatusOr<std::string> ECPointUtil::HashToCurve(
    absl::string_view input, ECCommutativeCipher::HashType hash_type) {
  if (hash_type == ECCommutativeCipher::HashType::SHA512) {
    ASSIGN_OR_RETURN(ECPoint point,
                     group_.GetPointByHashingToCurveSha512(input));
    return point.ToBytesCompressed();
  }

  if (hash_type == ECCommutativeCipher::HashType::SHA256) {
    ASSIGN_OR_RETURN(ECPoint point,
                     group_.GetPointByHashingToCurveSha256(input));
    return point.ToBytesCompressed();
  }

  return InvalidArgumentError("Invalid hash type.");
}

bool ECPointUtil::IsCurvePoint(absl::string_view input) {
  return group_.CreateECPoint(input).ok();
}

}  // namespace private_join_and_compute
