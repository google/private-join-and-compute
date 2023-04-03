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

#include "private_join_and_compute/crypto/mont_mul.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "private_join_and_compute/crypto/openssl.inc"

namespace private_join_and_compute {

MontBigNum::MontBigNum(const MontBigNum& other)
    : ctx_(other.ctx_),
      mont_ctx_(other.mont_ctx_),
      bn_(BigNum::BignumPtr(BN_dup(other.bn_.get()))) {}

MontBigNum& MontBigNum::operator=(const MontBigNum& other) {
  ctx_ = other.ctx_;
  mont_ctx_ = other.mont_ctx_;
  bn_ = BigNum::BignumPtr(BN_dup(other.bn_.get()));
  return *this;
}

MontBigNum::MontBigNum(MontBigNum&& other)
    : ctx_(other.ctx_), mont_ctx_(other.mont_ctx_), bn_(std::move(other.bn_)) {}

MontBigNum& MontBigNum::operator=(MontBigNum&& other) {
  ctx_ = other.ctx_;
  mont_ctx_ = other.mont_ctx_;
  bn_ = std::move(other.bn_);
  return *this;
}

// The reinterpret_cast is necessary to accept a string_view.
MontBigNum::MontBigNum(Context* ctx, BN_MONT_CTX* mont_ctx,
                       absl::string_view bytes)
    : MontBigNum(ctx, mont_ctx, BigNum::BignumPtr(BN_new())) {
  CRYPTO_CHECK(nullptr !=
               BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()),
                         bytes.size(), bn_.get()));
}

MontBigNum MontBigNum::Mul(const MontBigNum& mont_big_num) const {
  MontBigNum r = *this;
  r.MulInPlace(mont_big_num);
  return r;
}

MontBigNum& MontBigNum::MulInPlace(const MontBigNum& mont_big_num) {
  CHECK_EQ(mont_big_num.mont_ctx_, mont_ctx_);
  CRYPTO_CHECK(1 == BN_mod_mul_montgomery(bn_.get(), bn_.get(),
                                          mont_big_num.bn_.get(), mont_ctx_,
                                          ctx_->GetBnCtx()));
  return *this;
}

bool MontBigNum::operator==(const MontBigNum& other) const {
  CHECK_EQ(other.mont_ctx_, mont_ctx_);
  return BN_cmp(bn_.get(), other.bn_.get()) == 0;
}

MontBigNum MontBigNum::PowTo2To(int64_t exponent) const {
  CHECK(exponent >= 0) << "MontBigNum::PowTo2To: exponent must be nonnegative";
  MontBigNum r = *this;
  for (int64_t i = 0; i < exponent; i++) {
    CRYPTO_CHECK(1 == BN_mod_mul_montgomery(r.bn_.get(), r.bn_.get(),
                                            r.bn_.get(), mont_ctx_,
                                            ctx_->GetBnCtx()));
  }
  return r;
}

// The reinterpret_cast is necessary to return a string.
std::string MontBigNum::ToBytes() const {
  int length = BN_num_bytes(bn_.get());
  std::vector<unsigned char> bytes(length);
  BN_bn2bin(bn_.get(), bytes.data());
  return std::string(reinterpret_cast<char*>(bytes.data()), bytes.size());
}

BigNum MontBigNum::ToBigNum() const {
  BIGNUM* temp = BN_new();
  CHECK_NE(temp, nullptr);
  auto bn_ptr = BigNum::BignumPtr(temp);
  CRYPTO_CHECK(1 == BN_from_montgomery(bn_ptr.get(), bn_.get(), mont_ctx_,
                                       ctx_->GetBnCtx()));
  return ctx_->CreateBigNum(std::move(bn_ptr));
}

MontBigNum::MontBigNum(Context* ctx, BN_MONT_CTX* mont_ctx,
                       BigNum::BignumPtr bn)
    : ctx_(ctx), mont_ctx_(mont_ctx), bn_(std::move(bn)) {}

MontBigNum MontContext::CreateMontBigNum(const BigNum& big_num) {
  CHECK(big_num < modulus_);
  BIGNUM* bn = BN_dup(big_num.GetConstBignumPtr());
  CHECK_NE(bn, nullptr);
  CRYPTO_CHECK(1 ==
               BN_to_montgomery(bn, bn, mont_ctx_.get(), ctx_->GetBnCtx()));
  return MontBigNum(ctx_, mont_ctx_.get(), BigNum::BignumPtr(bn));
}

MontBigNum MontContext::CreateMontBigNum(absl::string_view bytes) {
  return MontBigNum(ctx_, mont_ctx_.get(), bytes);
}

MontContext::MontContext(Context* ctx, const BigNum& modulus)
    : modulus_(modulus), ctx_(ctx), mont_ctx_(MontCtxPtr(BN_MONT_CTX_new())) {
  CRYPTO_CHECK(1 == BN_MONT_CTX_set(mont_ctx_.get(),
                                    modulus.GetConstBignumPtr(),
                                    ctx_->GetBnCtx()));
}

}  // namespace private_join_and_compute
