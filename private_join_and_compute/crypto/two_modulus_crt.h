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

// Computes Chinese remainder theorem for two coprimes (i.e., relatively
// primes).

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_TWO_MODULUS_CRT_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_TWO_MODULUS_CRT_H_

#include "private_join_and_compute/crypto/big_num.h"

namespace private_join_and_compute {

class TwoModulusCrt {
 public:
  TwoModulusCrt(const BigNum& coprime1, const BigNum& coprime2);

  // TwoModulusCrt is neither copyable nor movable.
  TwoModulusCrt(const TwoModulusCrt&) = delete;
  TwoModulusCrt& operator=(const TwoModulusCrt&) = delete;

  ~TwoModulusCrt() = default;

  // Computes r s.t. r congruent to both solution1 mod coprime1 and
  // solution2 mod coprime2.
  BigNum Compute(const BigNum& solution1, const BigNum& solution2) const;

  // Returns the product of the two coprime values given to the constructor as
  // input.
  BigNum GetCoprimeProduct() const;

 private:
  BigNum crt_term1_;
  BigNum crt_term2_;
  BigNum coprime_product_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_TWO_MODULUS_CRT_H_
