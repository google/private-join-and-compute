/*
 * Copyright 2019 Google Inc.
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

#include "crypto/ec_group.h"

#include <algorithm>
#include <utility>

#include "glog/logging.h"
#include "crypto/ec_point.h"
#include "crypto/openssl.inc"
#include "util/status.inc"
#include "util/status_macros.h"
#include "absl/strings/str_cat.h"

namespace private_join_and_compute {

using util::Status;
using util::StatusOr;

namespace {

// Returns a group using the predefined underlying operations suggested by
// OpenSSL.
StatusOr<ECGroup::ECGroupPtr> CreateGroup(int curve_id) {
  auto ec_group_ptr = EC_GROUP_new_by_curve_name(curve_id);
  // If this fails, this is usually due to an invalid curve id.
  if (ec_group_ptr == nullptr) {
    return util::InvalidArgumentError(
        absl::StrCat("ECGroup::CreateGroup() - Could not create group. ",
                     OpenSSLErrorString()));
  }
  return ECGroup::ECGroupPtr(ec_group_ptr);
}

// Returns the order of the group. For more information, see
// https://en.wikipedia.org/wiki/Elliptic-curve_cryptography#Domain_parameters.
StatusOr<BigNum> CreateOrder(const EC_GROUP* group, Context* context) {
  BIGNUM* bn = BN_new();
  if (bn == nullptr) {
    return util::InternalError(
        absl::StrCat("ECGroup::CreateOrder - Could not create BIGNUM. ",
                     OpenSSLErrorString()));
  }
  BigNum::BignumPtr order = BigNum::BignumPtr(bn);
  if (EC_GROUP_get_order(group, order.get(), context->GetBnCtx()) != 1) {
    return util::InternalError(
        absl::StrCat("ECGroup::CreateOrder - Could not get order. ",
                     OpenSSLErrorString()));
  }
  return context->CreateBigNum(std::move(order));
}

// Returns the parameters that define the curve. For more information, see
// https://en.wikipedia.org/wiki/Elliptic-curve_cryptography#Domain_parameters.
StatusOr<ECGroup::CurveParams> CreateCurveParams(const EC_GROUP* group,
                                                 Context* context) {
  BIGNUM* bn1 = BN_new();
  BIGNUM* bn2 = BN_new();
  BIGNUM* bn3 = BN_new();
  if (bn1 == nullptr || bn2 == nullptr || bn3 == nullptr) {
    return util::InternalError(
        absl::StrCat("ECGroup::CreateCurveParams - Could not create BIGNUM. ",
                     OpenSSLErrorString()));
  }
  BigNum::BignumPtr p = BigNum::BignumPtr(bn1);
  BigNum::BignumPtr a = BigNum::BignumPtr(bn2);
  BigNum::BignumPtr b = BigNum::BignumPtr(bn3);
  if (EC_GROUP_get_curve_GFp(group, p.get(), a.get(), b.get(),
                             context->GetBnCtx()) != 1) {
    return util::InternalError(
        absl::StrCat("ECGroup::CreateCurveParams - Could not get params. ",
                     OpenSSLErrorString()));
  }
  BigNum p_bn = context->CreateBigNum(std::move(p));
  if (!p_bn.IsPrime()) {
    return util::InternalError(
        absl::StrCat("ECGroup::CreateCurveParams - p is not prime. ",
                     OpenSSLErrorString()));
  }
  return ECGroup::CurveParams{std::move(p_bn),
                              context->CreateBigNum(std::move(a)),
                              context->CreateBigNum(std::move(b))};
}

// Returns (p - 1) / 2 where p is a curve-defining parameter.
BigNum GetPMinusOneOverTwo(const ECGroup::CurveParams& curve_params,
                           Context* context) {
  return (curve_params.p - context->One()) / context->Two();
}

}  // namespace

ECGroup::ECGroup(Context* context, ECGroupPtr group, BigNum order,
                 CurveParams curve_params, BigNum p_minus_one_over_two)
    : context_(context),
      group_(std::move(group)),
      order_(std::move(order)),
      curve_params_(std::move(curve_params)),
      p_minus_one_over_two_(std::move(p_minus_one_over_two)) {}

StatusOr<ECGroup> ECGroup::Create(int curve_id, Context* context) {
  ECGroupPtr g = RETURN_OR_ASSIGN(CreateGroup(curve_id));
  BigNum order = RETURN_OR_ASSIGN(CreateOrder(g.get(), context));
  CurveParams params = RETURN_OR_ASSIGN(CreateCurveParams(g.get(), context));
  BigNum p_minus_one_over_two = GetPMinusOneOverTwo(params, context);
  return ECGroup(context, std::move(g), std::move(order), std::move(params),
                 std::move(p_minus_one_over_two));
}

BigNum ECGroup::GeneratePrivateKey() const {
  return context_->GenerateRandBetween(context_->One(), order_);
}

Status ECGroup::CheckPrivateKey(const BigNum& priv_key) const {
  if (context_->Zero() >= priv_key || priv_key >= order_) {
    return util::InvalidArgumentError(
        "The given key is out of bounds, needs to be in [1, order) instead.");
  }
  return ::util::OkStatus();
}

StatusOr<ECPoint> ECGroup::GetPointByHashingToCurve(
    const std::string& m) const {
  BigNum x = context_->RandomOracle(m, curve_params_.p);
  while (true) {
    x = x.Mod(curve_params_.p);
    BigNum y2 = ComputeYSquare(x);
    if (IsSquare(y2)) {
      BigNum sqrt = y2.ModSqrt(curve_params_.p);
      if (sqrt.IsBitSet(0)) {
        return CreateECPoint(x, sqrt.ModNegate(curve_params_.p));
      }
      return CreateECPoint(x, sqrt);
    }
    x = context_->RandomOracle(x.ToBytes(), curve_params_.p);
  }
}

BigNum ECGroup::ComputeYSquare(const BigNum& x) const {
  return (x.Exp(context_->Three()) + curve_params_.a * x + curve_params_.b)
      .Mod(curve_params_.p);
}

bool ECGroup::IsValid(const ECPoint& point) const {
  if (!IsOnCurve(point) || IsAtInfinity(point)) {
    return false;
  }
  return true;
}

bool ECGroup::IsOnCurve(const ECPoint& point) const {
  return 1 == EC_POINT_is_on_curve(group_.get(), point.point_.get(),
                                   context_->GetBnCtx());
}

bool ECGroup::IsAtInfinity(const ECPoint& point) const {
  return 1 == EC_POINT_is_at_infinity(group_.get(), point.point_.get());
}

bool ECGroup::IsSquare(const BigNum& q) const {
  return q.ModExp(p_minus_one_over_two_, curve_params_.p).IsOne();
}

StatusOr<ECPoint> ECGroup::GetFixedGenerator() const {
  const EC_POINT* ssl_generator = EC_GROUP_get0_generator(group_.get());
  EC_POINT* dup_ssl_generator = EC_POINT_dup(ssl_generator, group_.get());
  if (dup_ssl_generator == nullptr) {
    return util::InternalError(OpenSSLErrorString());
  }
  return ECPoint(group_.get(), context_->GetBnCtx(),
                 ECPoint::ECPointPtr(dup_ssl_generator));
}

StatusOr<ECPoint> ECGroup::GetRandomGenerator() const {
  ECPoint generator = RETURN_OR_ASSIGN(GetFixedGenerator());
  return generator.Mul(context_->GenerateRandBetween(context_->One(), order_));
}

StatusOr<ECPoint> ECGroup::CreateECPoint(const BigNum& x,
                                         const BigNum& y) const {
  ECPoint point = ECPoint(group_.get(), context_->GetBnCtx(), x, y);
  if (!IsValid(point)) {
    return util::InvalidArgumentError(
        "ECGroup::CreateECPoint(x,y) - The point is not valid.");
  }
  return std::move(point);
}

StatusOr<ECPoint> ECGroup::CreateECPoint(const std::string& bytes) const {
  ECPoint::ECPointPtr point(RETURN_IF_NULL(EC_POINT_new(group_.get())));
  if (EC_POINT_oct2point(group_.get(), point.get(),
                         reinterpret_cast<const unsigned char*>(bytes.data()),
                         bytes.size(), context_->GetBnCtx()) != 1) {
    return util::InvalidArgumentError(
        absl::StrCat("ECGroup::CreateECPoint(string) - Could not decode point.",
                     "\n", OpenSSLErrorString()));
  }

  ECPoint ec_point(group_.get(), context_->GetBnCtx(), std::move(point));
  if (!IsValid(ec_point)) {
    return util::InvalidArgumentError(
        "ECGroup::CreateECPoint(string) - Decoded point is not valid.");
  }
  return std::move(ec_point);
}

StatusOr<ECPoint> ECGroup::GetPointAtInfinity() const {
  EC_POINT* new_point = EC_POINT_new(group_.get());
  if (new_point == nullptr) {
    return util::InternalError(
        "ECGroup::GetPointAtInfinity() - Could not create new point.");
  }
  ECPoint::ECPointPtr point(new_point);
  if (EC_POINT_set_to_infinity(group_.get(), point.get()) != 1) {
    return util::InternalError(
        "ECGroup::GetPointAtInfinity() - Could not get point at infinity.");
  }
  ECPoint ec_point(group_.get(), context_->GetBnCtx(), std::move(point));
  return std::move(ec_point);
}

}  // namespace private_join_and_compute
