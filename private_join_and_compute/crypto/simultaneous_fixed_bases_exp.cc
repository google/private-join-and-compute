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

#include "private_join_and_compute/crypto/simultaneous_fixed_bases_exp.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/mont_mul.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

namespace internal {

template <typename Element>
StatusOr<Element> Clone(const Element& element);

template <typename Element, typename Context>
StatusOr<Element> Mul(const Element& e1, const Element& e2,
                      const Context& context);

template <typename Element>
bool IsZero(const Element& c);

template <>
StatusOr<private_join_and_compute::BigNum> Clone(
    const private_join_and_compute::BigNum& element) {
  return element;
}

template <>
bool IsZero(const private_join_and_compute::BigNum& c) {
  return c.IsOne();
}

template <>
StatusOr<ZnElement> Mul(const ZnElement& e1, const ZnElement& e2,
                        const ZnContext& context) {
  return e1.ModMul(e2, context.modulus);
}

template <>
StatusOr<private_join_and_compute::MontBigNum> Clone(
    const private_join_and_compute::MontBigNum& element) {
  return element;
}

template <>
StatusOr<private_join_and_compute::MontBigNum> Mul(
    const private_join_and_compute::MontBigNum& e1,
    const private_join_and_compute::MontBigNum& e2,
    const private_join_and_compute::MontContext& context) {
  return e1.Mul(e2);
}

template <>
bool IsZero(const private_join_and_compute::MontBigNum& c) {
  return c.ToBigNum().IsOne();
}

}  // namespace internal

template <typename Element, typename Context>
SimultaneousFixedBasesExp<Element, Context>::SimultaneousFixedBasesExp(
    size_t num_bases, size_t num_simultaneous, size_t num_batches,
    std::unique_ptr<Element> zero, std::unique_ptr<Context> context,
    std::vector<std::vector<std::unique_ptr<Element>>> table)
    : num_bases_(num_bases),
      num_simultaneous_(num_simultaneous),
      num_batches_(num_batches),
      zero_(std::move(zero)),
      context_(std::move(context)),
      precomputed_table_(std::move(table)) {}

template <typename Element, typename Context>
StatusOr<std::unique_ptr<SimultaneousFixedBasesExp<Element, Context>>>
SimultaneousFixedBasesExp<Element, Context>::Create(
    const std::vector<Element>& bases, const Element& zero,
    size_t num_simultaneous, std::unique_ptr<Context> context) {
  if (num_simultaneous == 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("The num_simultaneous parameter, ", num_simultaneous,
                     ", should be positive."));
  }
  if (num_simultaneous > bases.size()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "The num_simultaneous parameter, ", num_simultaneous,
        ", can be at most the number of bases", bases.size(), "."));
  }
  size_t num_batches = (bases.size() + num_simultaneous - 1) / num_simultaneous;
  ASSIGN_OR_RETURN(auto zero_clone, internal::Clone(zero));
  std::unique_ptr<Element> zero_ptr =
      std::make_unique<Element>(std::move(zero_clone));
  ASSIGN_OR_RETURN(std::vector<std::vector<std::unique_ptr<Element>>> table,
                   SimultaneousFixedBasesExp::Precompute(
                       bases, zero, *context, num_simultaneous, num_batches));
  return absl::WrapUnique<SimultaneousFixedBasesExp>(
      new SimultaneousFixedBasesExp(bases.size(), num_simultaneous, num_batches,
                                    std::move(zero_ptr), std::move(context),
                                    std::move(table)));
}

template <typename Element, typename Context>
StatusOr<std::vector<std::vector<std::unique_ptr<Element>>>>
SimultaneousFixedBasesExp<Element, Context>::Precompute(
    const std::vector<Element>& bases, const Element& zero,
    const Context& context, size_t num_simultaneous, size_t num_batches) {
  std::vector<std::vector<std::unique_ptr<Element>>> table;
  for (size_t i = 0; i < num_batches; ++i) {
    table.push_back({});
    ASSIGN_OR_RETURN(Element zero_clone, internal::Clone(zero));
    table[i].push_back(std::make_unique<Element>(std::move(zero_clone)));
    const size_t start = i * num_simultaneous;
    const size_t num_items_in_batch =
        std::min(bases.size() - start, num_simultaneous);
    int highest_one_bit = 0;
    // Generate all values (c1, ..., ck) in {0, 1}^k using the binary
    // representation of integers between [0, 2^k - 1].
    for (int j = 1; j < (1 << num_items_in_batch); ++j) {
      if (j & (1 << (highest_one_bit + 1))) {
        ++highest_one_bit;
      }
      size_t prev = j - (1 << highest_one_bit);
      if (prev == 0) {
        ASSIGN_OR_RETURN(Element clone,
                         internal::Clone(bases[start + highest_one_bit]));
        table[i].push_back(std::make_unique<Element>(std::move(clone)));
      } else {
        ASSIGN_OR_RETURN(
            Element add,
            internal::Mul(*(table[i][prev]), bases[start + highest_one_bit],
                          context));
        table[i].push_back(std::make_unique<Element>(std::move(add)));
      }
    }
  }
  return std::move(table);
}

template <typename Element, typename Context>
StatusOr<Element> SimultaneousFixedBasesExp<Element, Context>::SimultaneousExp(
    const std::vector<private_join_and_compute::BigNum>& exponents) const {
  if (exponents.size() != num_bases_) {
    return absl::InvalidArgumentError(
        absl::StrCat("Number of exponents, ", exponents.size(), ", and bases,",
                     num_bases_, ", are not equal."));
  }
  int max_bit_length = 0;
  for (const auto& exponent : exponents) {
    if (exponent.BitLength() > max_bit_length) {
      max_bit_length = exponent.BitLength();
    }
  }
  ASSIGN_OR_RETURN(Element result, internal::Clone(*zero_));
  for (int i = max_bit_length - 1; i >= 0; --i) {
    if (!internal::IsZero(result)) {
      ASSIGN_OR_RETURN(result, internal::Mul(result, result, *context_));
    }
    for (size_t j = 0; j < num_batches_; ++j) {
      size_t precompute_idx = 0;
      size_t batch_size = num_simultaneous_;
      if (batch_size > num_bases_ - (j * num_simultaneous_)) {
        batch_size = num_bases_ - (j * num_simultaneous_);
      }
      for (size_t k = 0; k < batch_size; ++k) {
        size_t data_idx = (j * num_simultaneous_) + k;
        if (exponents[data_idx].IsBitSet(i)) {
          precompute_idx += (1 << k);
        }
      }
      if (precompute_idx) {
        ASSIGN_OR_RETURN(
            result,
            internal::Mul(result, *(precomputed_table_[j][precompute_idx]),
                          *context_));
      }
    }
  }
  return std::move(result);
}

template class SimultaneousFixedBasesExp<private_join_and_compute::MontBigNum,
                                         private_join_and_compute::MontContext>;
template class SimultaneousFixedBasesExp<ZnElement, ZnContext>;

}  // namespace private_join_and_compute
