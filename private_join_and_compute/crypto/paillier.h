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

// Implementation of the Damgaard-Jurik cryptosystem.
// Damgaard, Ivan, Mads Jurik, and Jesper Buus Nielsen. "A generalization of
// Paillier's public-key system with applications to electronic voting."
// International Journal of Information Security 9.6 (2010): 371-385.
// This header defines two classes:
// (1) PublicPaillier defining homomorphic operations (i.e., Add, Multiply and
//     LeftShift) and also the Encrypt function using the public key.
// (2) PrivatePaillier defining Decrypt and a more efficient Encrypt function
//     than the one in PublicPaillier by utilizing the private key.
// One example usage (the possible usages of these two classes are by no means
// limited to this one):
//          Alice                                            Bob
//   +-------------------------------+          +------------------------------+
//   |                               |          |                              |
//   |Context ctx;                   |          |                              |
//   |BigNum p =                     |          |                              |
//   |  ctx.GenerateSafePrime(512)   |          |                              |
//   |BigNum q =                     |          |                              |
//   |  ctx.GenerateSafePrime(512)   | n and s  |                              |
//   |BigNum n = p * q;              +---------->Context ctx;                  |
//   |                               |          |                              |
//   |PrivatePaillier pp(&ctx, n, s);|          |PublicPaillier pp(&ctx, n, s);|
//   |                               |          |                              |
//   |String ct1 = pp.Encrypt(m1);   |          |                              |
//   |...                            |   ct1..k |                              |
//   |String ctk = pp.Encrypt(mk);   +---------->Shuffle ct1..k                |
//   |                               |          |Generate random BigNum r1..k  |
//   |                               |          |such that mi+ri is less than  |
//   |                               |          |n^s for any i in 1..k         |
//   |                               |          |BigNum rcti = pp.Encrypt(     |
//   |                               |          |  ri.ToBytes())  for i in 1..k|
//   |                               |  ct1..k  |cti = pp.Add(cti, rcti)       |
//   |BigNum mri = pp.Decrypt(cti)   <----------+  for i in 1..k               |
//   |  for i in 1..k                |          |                              |
//   |// mri = mj + ri               |          |                              |
//   |// where only Bob knows i->j   |          |                              |
//   +-------------------------------+          +------------------------------+

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PAILLIER_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PAILLIER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/paillier.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// A helper class for doing Paillier crypto for only one of the primes forming
// the composite number n.
class PrimeCrypto;
// A helper class that wraps a PrimeCrypto, that can additionally return the
// random number (used in an encryption) with the ciphertext.
class PrimeCryptoWithRand;

class FixedBaseExp;
class TwoModulusCrt;

// Holds the resulting ciphertext from a Paillier encryption as well as the
// random number used.
struct PaillierEncAndRand {
  BigNum ciphertext;
  BigNum rand;
};

// Returns a Paillier public key and private key. The Paillier modulus n will be
// generated to be the product of safe primes p and q, each of modulus_length/2
// bits. "s" is the Damgard-Jurik parameter: the corresponding message space is
// n^s, and the ciphertext space is n^(s+1).
StatusOr<std::pair<PaillierPublicKey, PaillierPrivateKey>>
GeneratePaillierKeyPair(Context* ctx, int32_t modulus_length, int32_t s);

// The class defining Damgaard-Jurik cryptosystem operations that can be
// performed with the public key.
// Example:
//   std::unique_ptr<Context> ctx;
//   BigNum n = ctx->CreateBigNum(n_in_bytes);
//   std::unique_ptr<PublicPaillier> public_paillier(
//       new PublicPaillier(ctx.get(), n, 2));
//   BigNum ciphertext = public_paillier->Encrypt(message);
//
// This class is not thread-safe since Context is not thread-safe.
// Note that this class does *not* take the ownership of Context.
class PublicPaillier {
 public:
  // Creates a generic PublicPaillier with the public key n and s.
  // n is a composite number equals to p * q where p and q are safe primes and
  // private.
  // n^s is the plaintext size and n^(s+1) is the ciphertext size.
  PublicPaillier(Context* ctx, const BigNum& n, int s);

  // Creates a PublicPaillier equivalent to the original Paillier cryptosystem
  // (i.e., s = 1)
  // n is the plaintext size and n^2 is the ciphertext size.
  PublicPaillier(Context* ctx, const BigNum& n);

  // Creates a PublicPaillier from the given proto.
  PublicPaillier(Context* ctx, const PaillierPublicKey& public_key_proto);

  // PublicPaillier is neither copyable nor movable.
  PublicPaillier(const PublicPaillier&) = delete;
  PublicPaillier& operator=(const PublicPaillier&) = delete;

  ~PublicPaillier();

  // Adds two ciphertexts homomorphically such that the result is an
  // encryption of the sum of the two plaintexts.
  BigNum Add(const BigNum& ciphertext1, const BigNum& ciphertext2) const;

  // Multiplies a ciphertext homomorphically such that the result is an
  // encryption of the product of the plaintext and the multiplier.
  // Note that multiplier should *not* be encrypted.
  BigNum Multiply(const BigNum& ciphertext, const BigNum& multiplier) const;

  // Left shifts a ciphertext homomorphically such that the result is an
  // encryption of the plaintext left shifted by shift_amount.
  BigNum LeftShift(const BigNum& ciphertext, int shift_amount) const;

  // Encrypts the message and returns the ciphertext equivalent to:
  // (1+n)^message * g^random mod n^(s+1), where g is the generator chosen
  // during setup.
  // Returns INVALID_ARGUMENT status when the message is < 0 or >= n^s.
  StatusOr<BigNum> Encrypt(const BigNum& message) const;

  // Encrypts the message similar to Encrypt, but uses a provided random
  // value. It uses the generator g for a subgroup of n^s-th residues to speed
  // up encryption, by computing (1+n)^message * generator^random mod n^(s+1).
  // See DJN section 4.2 for more details.
  // Returns INVALID_ARGUMENT if rand is not less than or equal to n.
  // Assumes the message is already in the right range.
  // It is the caller's responsibility to ensure the randomness of rand.
  StatusOr<BigNum> EncryptUsingGeneratorAndRand(const BigNum& message,
                                                const BigNum& rand) const;

  // Encrypts the message similar to Encrypt, but uses a provided random
  // value. It computes the ciphertext directly (without the generator), as
  // (1+n)^message * random^(n^s) mod n^(s+1).
  // It contains an expensive exponentiation since n^s is large
  // Returns INVALID_ARGUMENT if rand is not in Zn*.
  // Assumes the message is already in the right range.
  // It is the caller's responsibility to ensure the randomness of rand.
  StatusOr<BigNum> EncryptWithRand(const BigNum& message,
                                   const BigNum& rand) const;

  // Encrypts the message by generating a random number and using
  // EncryptWithRand, additionally retaining the random number used and
  // returning it with the ciphertext.
  StatusOr<PaillierEncAndRand> EncryptAndGetRand(const BigNum& message) const;

  const BigNum& n() const { return n_; }
  int s() const { return s_; }

 private:
  // Factory class for creating BigNums and holding the temporary values for
  // the BigNum arithmetic operations. Ownership is not taken.
  Context* const ctx_;
  // Composite BigNum of two large primes.
  const BigNum n_;
  const int s_;
  // Vector containing the n powers upto s+1 for faster computation.
  const std::vector<BigNum> n_powers_;
  // n^(s+1)
  const BigNum modulus_;
  // generator of the subgroup of n^s-th residues mod n^s+1. Used for faster
  // computation of the random component r of the ciphertext.
  std::unique_ptr<FixedBaseExp> g_n_fbe_;
  // The vector holding values that are computed repeatedly when encrypting
  // arbitrary messages via computing the binomial expansion of (1+n)^message.
  // The binomial expansion of (1+n) to some arbitrary exponent has constant
  // factors depending on only 1, n, and s regardless of the exponent value,
  // this vector holds each of these fixed values for faster computation.
  // Refer to Section 4.2 "Optimization of Encryption" from the
  // Damgaard-Jurik-Nielsen paper for more information.
  const std::vector<BigNum> precomp_;
};

// The class defining Damgaard-Jurik cryptosystem operations that can be
// performed with the private key.
// This does not include the homomorphic operations as they are irrelevant when
// the private key is present. Use PublicPaillier for these operations.
// Example:
//   std::unique_ptr<Context> ctx;
//   BigNum p = ctx->CreateBigNum(p_in_bytes);
//   BigNum q = ctx->CreateBigNum(q_in_bytes);
//   std::unique_ptr<PrivatePaillier> private_paillier(
//       new PrivatePaillier(ctx.get(), p, q, 2));
//   BigNum ciphertext = private_paillier->Encrypt(message);
//   BigNum message_as_bignum = private_paillier->Decrypt(ciphertext);
//
// This class is not thread-safe since Context is not thread-safe.
// Note that this class does *not* take the ownership of Context.
class PrivatePaillier {
 public:
  // Creates a PrivatePaillier using the s value and the private key p and q.
  // p and q are safe primes and (p*q)^s is the plaintext size and (p*q)^(s+1)
  // is the ciphertext size.
  PrivatePaillier(Context* ctx, const BigNum& p, const BigNum& q, int s);

  // Creates a PrivatePaillier equivalent to the original Paillier cryptosystem
  // (i.e., s = 1)
  PrivatePaillier(Context* ctx, const BigNum& p, const BigNum& q);

  // Creates a PrivatePaillier from the supplied key proto.
  PrivatePaillier(Context* ctx, const PaillierPrivateKey& private_key_proto);

  // PrivatePaillier is neither copyable nor movable.
  PrivatePaillier(const PrivatePaillier&) = delete;
  PrivatePaillier& operator=(const PrivatePaillier&) = delete;

  // Needed to avoid default inline one so that forward declaration works.
  ~PrivatePaillier();

  // Encrypts the message and returns the ciphertext equivalent (in security) to
  // (1+n)^message * random^(n^s) mod n^(s+1).
  // This is more efficient than the encryption using the PublicPaillier due to:
  // 1) Doing computation on each safe prime (half the size of n) and combine
  //    the two result with Chinese Remainder Theorem.
  // 2) For each safe prime part, we can convert random^(n^s) into g^random
  //    where g is a fixed generator. This decreases the number of modular
  //    multiplications done from O(slogn) to O(logn). Given a fast fixed based
  //    exponentiation is used rather than naively computing g^random in each
  //    time Encrypt is called, this O(logn) complexity can be further improved
  //    relatively to the used method effectiveness.
  //
  // Returns INVALID_ARGUMENT status when the message is < 0 or >= n^s.
  StatusOr<BigNum> Encrypt(const BigNum& message) const;

  // Decrypts the ciphertext and returns the message inside as a BigNum.
  // Uses the algorithm from the Theorem 1 in Damgaard-Jurik-Nielsen paper.
  // This method also benefits from computing the decryption for each safe prime
  // part separately and then combining them together with the Chinese Remainder
  // Theorem.
  // Returns INVALID_ARGUMENT status when the ciphertext is < 0 or >= n^(s+1).
  StatusOr<BigNum> Decrypt(const BigNum& ciphertext) const;

 private:
  friend class PrivatePaillierWithRand;
  // Factory class for creating BigNums and holding the temporary values for
  // the BigNum arithmetic operations. Ownership is not taken.
  Context* const ctx_;
  // (p*q)^s
  const BigNum n_to_s_;
  // (p*q)^(s+1)
  const BigNum n_to_s_plus_one_;
  // Helper defining Encrypt and Decrypt for the safe prime, p.
  std::unique_ptr<PrimeCrypto> p_crypto_;
  // Helper defining Encrypt and Decrypt for the safe prime, q.
  std::unique_ptr<PrimeCrypto> q_crypto_;
  // Helper for combining two encryption computed with the above PrimeCrypto
  // helpers.
  std::unique_ptr<TwoModulusCrt> two_mod_crt_encrypt_;
  // Helper for combining two decryption computed with the above PrimeCrypto
  // helpers.
  std::unique_ptr<TwoModulusCrt> two_mod_crt_decrypt_;
};

// This class is similar to PrivatePaillier, but it can additionally report
// the last random used in encryption.
class PrivatePaillierWithRand {
 public:
  // Creates a PrivatePaillierWithRand from the given PrivatePaillier.
  explicit PrivatePaillierWithRand(PrivatePaillier* private_paillier);

  // PrivatePaillier is neither copyable nor movable.
  PrivatePaillierWithRand(const PrivatePaillierWithRand&) = delete;
  PrivatePaillierWithRand& operator=(const PrivatePaillierWithRand&) = delete;

  ~PrivatePaillierWithRand();

  // Encrypt with the underlying PrivatePaillier.
  StatusOr<BigNum> Encrypt(const BigNum& message) const;

  // Encrypts and returns the random used in the encryption.
  // Internally two random numbers are used which must be combined with a crt
  // calculation.
  //
  // crt((g_p^r1)^(n^s), (g_q^r2)^(n^s)) = r^(n^s) where crt coprimes are
  // p^(s+1) and q^(s+1). This can be rewritten as
  // crt(g_p^r1, g_q^r2) = r where crt coprimes are p and q.
  StatusOr<PaillierEncAndRand> EncryptAndGetRand(const BigNum& message) const;

  // Decrypt with the underlying PrivatePaillier.
  StatusOr<BigNum> Decrypt(const BigNum& ciphertext) const;

 private:
  Context* const ctx_;
  const PrivatePaillier* const private_paillier_;
  // Helper to combine the two random numbers kept in the two PrimeCrypto
  // instances within the PrivatePaillier.
  std::unique_ptr<TwoModulusCrt> two_mod_crt_rand_;
  // Helpers defining Encrypt and Decrypt for the safe primes p and q, that can
  // additionally return the random number (used in an encryption) with the
  // ciphertext.
  std::unique_ptr<PrimeCryptoWithRand> p_crypto_;
  std::unique_ptr<PrimeCryptoWithRand> q_crypto_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_PAILLIER_H_
