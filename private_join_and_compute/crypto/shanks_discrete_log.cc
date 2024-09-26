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

#include "private_join_and_compute/crypto/shanks_discrete_log.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// The maximum number of bits in the message (exponent).
const int ShanksDiscreteLog::kMaxMessageSize = 40;

ShanksDiscreteLog::ShanksDiscreteLog(
    private_join_and_compute::Context* ctx,
    const private_join_and_compute::ECGroup* group,
    std::unique_ptr<private_join_and_compute::ECPoint> generator,
    int max_message_bits, int precompute_bits,
    std::map<std::string, int> precomputed_table)
    : ctx_(ctx),
      generator_(std::move(generator)),
      max_message_bits_(max_message_bits),
      precompute_bits_(precompute_bits),
      precomputed_table_(std::move(precomputed_table)) {}

absl::StatusOr<std::map<std::string, int>> ShanksDiscreteLog::PrecomputeTable(
    const private_join_and_compute::ECGroup* group,
    const private_join_and_compute::ECPoint* generator, int precompute_bits) {
  std::map<std::string, int> table;
  ASSIGN_OR_RETURN(auto point, group->GetPointAtInfinity());
  // Cannot encode point at infinity to bytes.
  for (int i = 1; i < (1 << precompute_bits); ++i) {
    ASSIGN_OR_RETURN(point, generator->Add(point));
    ASSIGN_OR_RETURN(auto bytes, point.ToBytesCompressed());
    table.insert(std::pair<std::string, int>(bytes, i));
  }
  return table;
}

absl::StatusOr<std::unique_ptr<ShanksDiscreteLog>> ShanksDiscreteLog::Create(
    private_join_and_compute::Context* ctx,
    const private_join_and_compute::ECGroup* group,
    const private_join_and_compute::ECPoint* generator, int max_message_bits,
    int precompute_bits) {
  if (max_message_bits <= precompute_bits) {
    return absl::InvalidArgumentError(
        "Precompute bits should be at most the maximum message size.");
  }
  if (max_message_bits > kMaxMessageSize) {
    return absl::InvalidArgumentError(
        absl::StrCat("Maximum number of message bits should be at most ",
                     kMaxMessageSize, "."));
  }
  ASSIGN_OR_RETURN(auto generator_clone, generator->Clone());
  auto generator_ptr = std::make_unique<private_join_and_compute::ECPoint>(
      std::move(generator_clone));
  ASSIGN_OR_RETURN(auto table,
                   PrecomputeTable(group, generator, precompute_bits));
  return absl::WrapUnique<ShanksDiscreteLog>(new ShanksDiscreteLog(
      ctx, group, std::move(generator_ptr), max_message_bits, precompute_bits,
      std::move(table)));
}

absl::StatusOr<int64_t> ShanksDiscreteLog::GetDiscreteLog(
    const private_join_and_compute::ECPoint& point) {
  ASSIGN_OR_RETURN(auto inverse, generator_->Inverse());
  ASSIGN_OR_RETURN(auto baby_step,
                   inverse.Mul(ctx_->CreateBigNum(1 << precompute_bits_)));
  ASSIGN_OR_RETURN(auto current_state, point.Clone());
  // Create guarantees that max_message_bits_ >= precompute_bits_.
  for (int i = 0; i < (1 << (max_message_bits_ - precompute_bits_)); ++i) {
    // Infinity cannot be encoded as bytes, so we explcitly check for infinity
    // in precomputed table.
    if (current_state.IsPointAtInfinity()) {
      int64_t shift = 1;
      shift <<= precompute_bits_;
      return shift * i;
    }
    ASSIGN_OR_RETURN(auto bytes, current_state.ToBytesCompressed());
    auto iter = precomputed_table_.find(bytes);
    if (iter != precomputed_table_.end()) {
      int64_t shift = 1;
      shift <<= precompute_bits_;
      shift *= i;
      return shift + iter->second;
    }
    ASSIGN_OR_RETURN(current_state, current_state.Add(baby_step));
  }
  return absl::InvalidArgumentError(
      "Could not find discrete log. Exponent larger than specified max size.");
}

}  // namespace private_join_and_compute
