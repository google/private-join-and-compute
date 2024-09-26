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

#ifndef PRIVATE_JOIN_AND_COMPUTE_EC_POINT_UTIL_H_
#define PRIVATE_JOIN_AND_COMPUTE_EC_POINT_UTIL_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// ECPointUtil class to allow generating random EC points, hashing to the
// elliptic curve, and checking if strings encode curve points.

class ECPointUtil {
 public:
  // ECPointUtil is neither copyable nor assignable.
  ECPointUtil(const ECPointUtil&) = delete;
  ECPointUtil& operator=(const ECPointUtil&) = delete;

  // Creates an ECPointUtil object.
  // Returns INVALID_ARGUMENT status instead if the curve_id is not valid
  // or INTERNAL status when crypto operations are not successful.
  static StatusOr<std::unique_ptr<ECPointUtil>> Create(int curve_id);

  // Returns a random EC point on the curve
  StatusOr<std::string> GetRandomCurvePoint();

  // Hashes the given string to the curve.
  //
  // Suggested default hash_type is ECCommutativeCipher::HashType::Sha256.
  StatusOr<std::string> HashToCurve(absl::string_view input,
                                    ECCommutativeCipher::HashType hash_type);

  // Checks if a string represents a curve point.
  // May give a false negative if an internal error occurs.
  bool IsCurvePoint(absl::string_view input);

 private:
  ECPointUtil(std::unique_ptr<Context> context, ECGroup group);

  // Context used for storing temporary values to be reused across openssl
  // function calls for better performance.
  std::unique_ptr<Context> context_;

  // The EC Group representing the curve definition.
  ECGroup group_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_EC_POINT_UTIL_H_
