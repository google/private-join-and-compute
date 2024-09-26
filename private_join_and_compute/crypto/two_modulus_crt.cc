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

#include "private_join_and_compute/crypto/two_modulus_crt.h"

namespace private_join_and_compute {

TwoModulusCrt::TwoModulusCrt(const BigNum& coprime1, const BigNum& coprime2)
    : crt_term1_(coprime2 * coprime2.ModInverse(coprime1).value()),
      crt_term2_(coprime1 * coprime1.ModInverse(coprime2).value()),
      coprime_product_(coprime1 * coprime2) {}

BigNum TwoModulusCrt::Compute(const BigNum& solution1,
                              const BigNum& solution2) const {
  return ((solution1 * crt_term1_) + (solution2 * crt_term2_))
      .Mod(coprime_product_);
}

BigNum TwoModulusCrt::GetCoprimeProduct() const { return coprime_product_; }

}  // namespace private_join_and_compute
