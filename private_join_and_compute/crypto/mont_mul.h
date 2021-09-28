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

// Classes for doing Montgomery modular multiplications using OpenSSL libraries.
// Using these classes for modular multiplications is faster than using the
// BigNum ModMul when same values are multiplied multiple times.
// NOTE: These classes are best suited for computing multiple exponentiations of
// a fixed based number ordered by exponents value. For instance computing g^n,
// g^(n+1),... in order. For all modular exponentiations with different bases,
// BigNum's ModExp using OpenSSL BN_mod_exp would probably be faster since it
// also uses Montgomery modular multiplication under the hood.

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_MONT_MUL_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_MONT_MUL_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/openssl.inc"

namespace private_join_and_compute {

class MontBigNum {
 public:
  // Copies the given MontBigNum.
  MontBigNum(const MontBigNum& other);
  MontBigNum& operator=(const MontBigNum& other);

  // Moves the given MontBigNum.
  MontBigNum(MontBigNum&& other);
  MontBigNum& operator=(MontBigNum&& other);

  // Multiplies this and mont_big_num in Montgomery form and returns the
  // resulting MontBigNum.
  // Fails if mont_big_num is not created with the same MontContext used to
  // create this MontBigNum.
  MontBigNum Mul(const MontBigNum& mont_big_num) const;

  // Multiplies this and mont_big_num in Montgomery form and puts the result
  // into this MontBigNum.
  // Fails if mont_big_num is not created with the same MontContext used to
  // create this MontBigNum.
  MontBigNum& MulInPlace(const MontBigNum& mont_big_num);

  // Overloads *= operator to multiply this with another MontBigNum objects.
  // Returns a MontBigNum whose value is (a * b).
  inline MontBigNum& operator*=(const MontBigNum& other) {
    return this->MulInPlace(other);
  }

  // Overloads == operator to check for equality. Note there is no CompareTo
  // method in montgomery form.
  // Fails if other is not created with the same MontContext used to create this
  // MontBigNum.
  bool operator==(const MontBigNum& other) const;

  // Overloads inequality operator. Returns true if two MontBigNums differ.
  // Fails if other is not created with the same MontContext used to create this
  // MontBigNum.
  inline bool operator!=(const MontBigNum& other) const {
    return !(*this == other);
  }

  // Computes this^(2^exponent) in Montgomery form and returns the resulting
  // MontBigNum.
  MontBigNum PowTo2To(int64_t exponent) const;

  // Serializes this without converting to BigNum.
  std::string ToBytes() const;

  // Converts this MontBigNum to its original BigNum value.
  BigNum ToBigNum() const;

 private:
  // Creates a MontBigNum with the bn that is already in Montgomery form based
  // on the mont_ctx. Takes the ownership of bn.
  MontBigNum(Context* ctx, BN_MONT_CTX* mont_ctx, BigNum::BignumPtr bn);

  // Creates a MontBigNum from a byte string. Assumes the serialized number is
  // in montgomery form already.
  MontBigNum(Context* ctx, BN_MONT_CTX* mont_ctx, absl::string_view bytes);

  Context* ctx_;
  BN_MONT_CTX* mont_ctx_;
  BigNum::BignumPtr bn_;
  friend class MontContext;
};

// Overloads * operator to multiply two MontBigNum objects.
// Returns a MontBigNum whose value is (a * b).
inline MontBigNum operator*(const MontBigNum& a, const MontBigNum& b) {
  return a.Mul(b);
}

// Factory class for MontBigNum having the BN_MONT_CTX that is used to convert
// BigNums into their Montgomery forms based on a fixed modulus.
class MontContext {
 public:
  // Deletes a BN_MONT_CTX when it goes out of scope.
  class MontCtxDeleter {
   public:
    void operator()(BN_MONT_CTX* ctx) { BN_MONT_CTX_free(ctx); }
  };
  typedef std::unique_ptr<BN_MONT_CTX, MontCtxDeleter> MontCtxPtr;

  // Creates a MontBigNum based on the big_num after converting a copy of it.
  MontBigNum CreateMontBigNum(const BigNum& big_num);

  // Creates a MontBigNum from a byte string that was generated using ToBytes().
  // The original MontBigNum's context does not need to be the same as the
  // current MontContext, as long as their moduli are equal.
  MontBigNum CreateMontBigNum(absl::string_view bytes);

  // Creates MontContext based on the given modulus. Every operation on the
  // created MontBigNums using this MontContext will be done with this modulus.
  MontContext(Context* ctx, const BigNum& modulus);

  // MontContext is neither copyable nor movable.
  MontContext(const MontContext&) = delete;
  MontContext& operator=(const MontContext&) = delete;

 private:
  const BigNum modulus_;
  Context* const ctx_;
  MontCtxPtr mont_ctx_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_MONT_MUL_H_
