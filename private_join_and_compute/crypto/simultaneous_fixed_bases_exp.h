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

// Implementation of simultaneous fixed bases exponentation.
//
// As input, we receive a set of fixed bases b1, ..., bn. On each input of
// exponents e1, ..., en, we want to compute b1^e1 * ... * bn^en. This problem
// is commonly referred to as the simultaneous exponentiation problem.
//
// Our algorithm uses Straus's algorithm. See [1] for a full description.
//
// For any set of fixed bases, Straus's algorithm performs a precomputation
// based on the b1, ..., bn. The precomputation may be used multiple times
// for each many sets of exponents.
//
// [1] https://cr.yp.to/papers/pippenger.pdf

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_SIMULTANEOUS_FIXED_BASES_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_SIMULTANEOUS_FIXED_BASES_H_

#include <cstddef>
#include <memory>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// Template type definitions for elements of the multiplicative group mod n.
using ZnElement = BigNum;
struct ZnContext {
  private_join_and_compute::BigNum modulus;
};

template <typename Element, typename Context>
class SimultaneousFixedBasesExp {
 public:
  // Constructs an object that will return the product of several
  // exponentiations with respect to b1, ..., bn specified in bases.
  //
  // The bases vector represents the bases b1, ..., bn, which will be used for
  // simultaneous exponentiation. For each instantiation, the Mul, IsZero and
  // Clone operations need to be specified.
  //
  // The "zero" parameter should be a multiplicative identity for the
  // underlying group (e.g. what you could get if you exponentiate any of the
  // bases to 0).
  //
  // The num_simultaneous parameter determines amount of precomputation
  // that will be performed. The precomputed table will require
  // O(2^num_simultaneous * bases / num_simultaneous) elliptic curve additions
  // to construct. As a result, simultaneous exponents for any set of exponents
  // only O((bases * max_bit_length) / num_simultaneous) elliptic curve
  // additions are required to compute the simultaneous exponentiation where
  // max_bit_length is the maximum bit length of any exponent. The parameter
  // num_simultaneous may be independent of the number of bases. However, the
  // total precomputation is capped at 2^{number of bases}.
  //
  // Returns INVALID_ARGUMENT if num_simultaneous is larger than the number of
  // bases.
  static StatusOr<std::unique_ptr<SimultaneousFixedBasesExp>> Create(
      const std::vector<Element>& bases, const Element& zero,
      size_t num_simultaneous, std::unique_ptr<Context> context);

  // SimultaneousFixedBasesExp is not copyable.
  SimultaneousFixedBasesExp(const SimultaneousFixedBasesExp&) = delete;
  SimultaneousFixedBasesExp& operator=(const SimultaneousFixedBasesExp&) =
      delete;

  // Computes the product of b1^e1, ..., bn^en where b1, ..., bn are specified
  // in the Create function and e1, ..., en are arguments to SimultaneousExp.
  //
  // Returns INVALID_ARGUMENT if number of exponents is different than the
  // number of bases.
  StatusOr<Element> SimultaneousExp(
      const std::vector<private_join_and_compute::BigNum>& exponents) const;

 private:
  SimultaneousFixedBasesExp(
      size_t num_bases, size_t num_simultaneous, size_t num_batches,
      std::unique_ptr<Element> zero, std::unique_ptr<Context> context,
      std::vector<std::vector<std::unique_ptr<Element>>> table);

  // Precomputes a table. Splits bases into groups of num_simultaneous. The last
  // group may be smaller and contain all leftovers. For each group consisting
  // of bases b1, ..., bk, we precompute c1b1 + c2b2 + ... + ckbk over all 2^k
  // possible values of (c1, ..., ck) in {0, 1}^k.
  static StatusOr<std::vector<std::vector<std::unique_ptr<Element>>>>
  Precompute(const std::vector<Element>& bases, const Element& zero,
             const Context& context, size_t num_simultaneous,
             size_t num_batches);

  const size_t num_bases_;
  const size_t num_simultaneous_;
  const size_t num_batches_;
  const std::unique_ptr<Element> zero_;
  const std::unique_ptr<Context> context_;

  const std::vector<std::vector<std::unique_ptr<Element>>> precomputed_table_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_SIMULTANEOUS_FIXED_BASES_H_
