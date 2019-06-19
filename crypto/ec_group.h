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

#ifndef CRYPTO_EC_GROUP_H_
#define CRYPTO_EC_GROUP_H_

#include <memory>
#include <string>

#include "crypto/big_num.h"
#include "crypto/context.h"
#include "crypto/openssl.inc"

namespace util {
class Status;
template <typename T>
class StatusOr;
}  // namespace util

namespace private_join_and_compute {

class ECPoint;

// Wrapper class for openssl EC_GROUP.
class ECGroup {
 public:
  // Deletes a EC_GROUP.
  class ECGroupDeleter {
   public:
    void operator()(EC_GROUP* group) { EC_GROUP_free(group); }
  };
  typedef std::unique_ptr<EC_GROUP, ECGroupDeleter> ECGroupPtr;

  // Constructs a new ECGroup object for the given named curve id.
  // See openssl header obj_mac.h for the available built-in curves.
  // Use a well-known prime curve such as NID_secp224r1 recommended by NIST.
  // Returns INTERNAL error code if there is a failure in crypto operations.
  static util::StatusOr<ECGroup> Create(int curve_id, Context* context);

  // Generates a new private key. The private key is a cryptographically strong
  // pseudo-random number in the range (0, order).
  BigNum GeneratePrivateKey() const;

  // Verifies that the random key is a valid number in the range (0, order).
  // Returns Status::OK if the key is valid, otherwise returns INVALID_ARGUMENT.
  util::Status CheckPrivateKey(const BigNum& priv_key) const;

  // Hashes m to a point on the elliptic curve y^2 = x^3 + ax + b over a
  // prime field.
  // Returns an INVALID_ARGUMENT error code if an error occurs.
  //
  // Security: The number of operations required to hash a string depends on the
  // string, which could lead to a timing attack.
  util::StatusOr<ECPoint> GetPointByHashingToCurve(const std::string& m) const;

  // Returns y^2 for the given x. The returned value is computed as x^3 + ax + b
  // mod p, where a and b are the parameters of the curve.
  BigNum ComputeYSquare(const BigNum& x) const;

  // Returns a fixed generator for this group.
  // Returns an INTERNAL error code if it fails.
  util::StatusOr<ECPoint> GetFixedGenerator() const;

  // Returns a random generator for this group.
  // Returns an INTERNAL error code if it fails.
  util::StatusOr<ECPoint> GetRandomGenerator() const;

  // Creates an ECPoint from the given string.
  // Returns an INTERNAL error code if creating the point fails.
  // Returns an INVALID_ARGUMENT error code if the created point is not in this
  // group or if it is the point at infinity.
  util::StatusOr<ECPoint> CreateECPoint(const std::string& bytes) const;

  // The parameters describing an elliptic curve given by the equation
  // y^2 = x^3 + a * x + b over a prime field Fp.
  struct CurveParams {
    BigNum p;
    BigNum a;
    BigNum b;
  };

  // Returns the order.
  const BigNum& GetOrder() const { return order_; }

  // Creates an ECPoint which is the identity.
  util::StatusOr<ECPoint> GetPointAtInfinity() const;

 private:
  ECGroup(Context* context, ECGroupPtr group, BigNum order,
          CurveParams curve_params, BigNum p_minus_one_over_two);

  // Creates an ECPoint object with the given x, y affine coordinates.
  // Returns an INVALID_ARGUMENT error code if the point (x, y) is not in this
  // group or if it is the point at infinity.
  util::StatusOr<ECPoint> CreateECPoint(const BigNum& x, const BigNum& y) const;

  // Returns true if q is a quadratic residue modulo curve_params_.p_.
  bool IsSquare(const BigNum& q) const;

  // Checks if the given point is valid. Returns false if the point is not in
  // the group or if it is the point is at infinity.
  bool IsValid(const ECPoint& point) const;

  // Returns true if the given point is in the group.
  bool IsOnCurve(const ECPoint& point) const;

  // Returns true if the given point is at infinity.
  bool IsAtInfinity(const ECPoint& point) const;

  Context* context_;
  ECGroupPtr group_;
  // The order of this group.
  BigNum order_;
  // The parameters of the curve. These values are used to hash a number to a
  // point on the curve.
  CurveParams curve_params_;
  // Constant used to evaluate if a number is a quadratic residue.
  BigNum p_minus_one_over_two_;
};

}  // namespace private_join_and_compute

#endif  // CRYPTO_EC_GROUP_H_
