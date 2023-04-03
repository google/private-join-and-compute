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

// Implementation of discrete log algorithm.
//
// To solve discrete logarithms, we use the Baby Step, Giant Step algorithm
// (also known as Shanks algorithm). For a full description, see [1].
//
// This class will construct a table of precomputed values, which depend
// on the generator and the percompute_bits argument. The precomputed table
// can be reused to perform multiple discrete logarithms for the same generator.
//
// [1] https://en.wikipedia.org/wiki/Baby-step_giant-step

#ifndef CRYPTO_SHANKS_DISCRETE_LOG_H_
#define CRYPTO_SHANKS_DISCRETE_LOG_H_

#include <map>
#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/elgamal.h"

namespace private_join_and_compute {

class ShanksDiscreteLog {
 public:
  // Constructs an object that can solve discrete logs with respect to the
  // input generator.
  //
  // The max_message_bits parameter means the object can solve discrete logs for
  // exponents with at most max_message_bits.
  //
  // The precompute_bits parameter means that a precomputed table will be
  // constructed for the first precompute_bits. In particular, the precomputed
  // table will hold O(2^(precompute_bits)) entries, which requires
  // O(2^(precompute_bits)) elliptic curve additions to construct.
  //
  // Afterwards, discrete logarithm computation requires at most
  // O(2^(max_message_bits - precompute_bits)) elliptic curve additions.
  //
  // Returns INVALID_ARGUMENT when max_message_bits is strictly greater than 40
  // or precompute_bits is strictly greater than max_message_bits.
  // Returns INTERNAL on internal cryptographic errors.
  static absl::StatusOr<std::unique_ptr<ShanksDiscreteLog>> Create(
      private_join_and_compute::Context* ctx,
      const private_join_and_compute::ECGroup* group,
      const private_join_and_compute::ECPoint* generator, int max_message_bits,
      int precompute_bits);

  // ShanksDiscreteLog is neither copyable nor copy assignable.
  ShanksDiscreteLog(const ShanksDiscreteLog&) = delete;
  ShanksDiscreteLog& operator=(const ShanksDiscreteLog&) = delete;

  // GetDiscreteLog returns INVALID_ARGUMENT when point = g^x where x has
  // strictly more than max_message_bits_ bits. Also, returns INTERNAL
  // on internal cryptographic errors.
  absl::StatusOr<int64_t> GetDiscreteLog(
      const private_join_and_compute::ECPoint& point);

  // Maxmium message size in bits.
  static const int kMaxMessageSize;

 private:
  ShanksDiscreteLog(
      private_join_and_compute::Context* ctx,
      const private_join_and_compute::ECGroup* group,
      std::unique_ptr<private_join_and_compute::ECPoint> generator,
      int max_message_bits, int precompute_bits,
      std::map<std::string, int> precomputed_table);

  // Constructs a map such that the pair (g^i, i) appears
  // for all i = 0, ..., 2^(precompute_bits).
  static absl::StatusOr<std::map<std::string, int>> PrecomputeTable(
      const private_join_and_compute::ECGroup* group,
      const private_join_and_compute::ECPoint* generator, int precompute_bits);

  private_join_and_compute::Context* const ctx_;
  const std::unique_ptr<private_join_and_compute::ECPoint> generator_;
  const int max_message_bits_;
  const int precompute_bits_;

  const std::map<std::string, int> precomputed_table_;
};

}  // namespace private_join_and_compute

#endif  // CRYPTO_SHANKS_DISCRETE_LOG_H_
