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

// Implements various modular exponentiation methods to be used for modular
// exponentiation of fixed bases.
//
// A note on sophisticated methods: Although there are more efficient methods
// besides what is implemented here, the storage overhead and also limitation
// of BigNum representation in C++ might not make them quite as efficient as
// they are claimed to be. One such example is Lim-Lee method, it is twice as
// fast as the simple modular exponentiation in Python, the C++ implementation
// is actually slower on all possible parameters due to the overhead of
// transposing the two dimensional bit representation of the exponent.

#include "private_join_and_compute/crypto/fixed_base_exp.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/mont_mul.h"
#include "private_join_and_compute/util/status.inc"

ABSL_FLAG(bool, two_k_ary_exp, false,
          "Whether to use 2^k-ary fixed based exponentiation.");

namespace private_join_and_compute {

namespace internal {

class FixedBaseExpImplBase {
 public:
  FixedBaseExpImplBase(const BigNum& fixed_base, const BigNum& modulus)
      : fixed_base_(fixed_base), modulus_(modulus) {}

  // FixedBaseExpImplBase is neither copyable nor movable.
  FixedBaseExpImplBase(const FixedBaseExpImplBase&) = delete;
  FixedBaseExpImplBase& operator=(const FixedBaseExpImplBase&) = delete;

  virtual ~FixedBaseExpImplBase() = default;

  virtual BigNum ModExp(const BigNum& exp) const = 0;

  // Most of the fixed base exponentiators uses precomputed tables for faster
  // exponentiation so they need to know the fixed base and the modulus during
  // the object construction.
  const BigNum& GetFixedBase() const { return fixed_base_; }
  const BigNum& GetModulus() const { return modulus_; }

 private:
  BigNum fixed_base_;
  BigNum modulus_;
};

class SimpleBaseExpImpl : public FixedBaseExpImplBase {
 public:
  SimpleBaseExpImpl(const BigNum& fixed_base, const BigNum& modulus)
      : FixedBaseExpImplBase(fixed_base, modulus) {}

  BigNum ModExp(const BigNum& exp) const final {
    return GetFixedBase().ModExp(exp, GetModulus());
  }
};

// Uses the 2^k-ary technique proposed in
// Brauer, Alfred. "On addition chains." Bulletin of the American Mathematical
// Society 45.10 (1939): 736-739.
//
// This modular exponentiation is in average 20% faster than SimpleBaseExpImpl.
class TwoKAryFixedBaseExpImpl : public FixedBaseExpImplBase {
 public:
  TwoKAryFixedBaseExpImpl(Context* ctx, const BigNum& fixed_base,
                          const BigNum& modulus)
      : FixedBaseExpImplBase(fixed_base, modulus),
        ctx_(ctx),
        mont_ctx_(new MontContext(ctx, modulus)),
        cache_() {
    cache_.push_back(mont_ctx_->CreateMontBigNum(ctx_->CreateBigNum(1)));
    MontBigNum g = mont_ctx_->CreateMontBigNum(GetFixedBase());
    cache_.push_back(g);
    int16_t max_exp = 256;
    for (int i = 0; i < max_exp; ++i) {
      cache_.push_back(cache_.back() * g);
    }
  }

  // Returns the base^exp mod modulus
  // Implements the 2^k-ary method, a generalization of the "square and
  // multiply" exponentiation method. Since chars are iterated in the byte
  // string of exp, the most straight k to use is 8. Other k values can also be
  // used but this would complicate the exp bits iteration which adds a
  // substantial overhead making the exponentiation slower than using
  // SimpleBaseExpImpl. For instance, reading two bytes at a time and converting
  // it to a short by shifting and adding is not faster than using a single
  // byte.
  BigNum ModExp(const BigNum& exp) const final {
    MontBigNum z = cache_[0];  // Copying 1 is faster than creating it.
    std::string values = exp.ToBytes();
    for (auto it = values.cbegin(); it != values.cend(); ++it) {
      for (int j = 0; j < 8; ++j) {
        z *= z;
      }
      z *= cache_[static_cast<uint8_t>(*it)];
    }
    return z.ToBigNum();
  }

 private:
  Context* ctx_;
  std::unique_ptr<MontContext> mont_ctx_;
  std::vector<MontBigNum> cache_;
};

}  // namespace internal

FixedBaseExp::FixedBaseExp(internal::FixedBaseExpImplBase* impl)
    : impl_(std::unique_ptr<internal::FixedBaseExpImplBase>(impl)) {}

FixedBaseExp::~FixedBaseExp() = default;

StatusOr<BigNum> FixedBaseExp::ModExp(const BigNum& exp) const {
  if (!exp.IsNonNegative()) {
    return InvalidArgumentError(
        "FixedBaseExp::ModExp : Negative exponents not supported.");
  }
  return impl_->ModExp(exp);
}

std::unique_ptr<FixedBaseExp> FixedBaseExp::GetFixedBaseExp(
    Context* ctx, const BigNum& fixed_base, const BigNum& modulus) {
  if (absl::GetFlag(FLAGS_two_k_ary_exp)) {
    return std::unique_ptr<FixedBaseExp>(new FixedBaseExp(
        new internal::TwoKAryFixedBaseExpImpl(ctx, fixed_base, modulus)));
  } else {
    return std::unique_ptr<FixedBaseExp>(
        new FixedBaseExp(new internal::SimpleBaseExpImpl(fixed_base, modulus)));
  }
}

}  // namespace private_join_and_compute
