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

// Implementation of the Camenisch-Shoup cryptosystem.
//
// Jan Camenisch, Victor Shoup. "Practical verifiable
// encryption and decryption of discrete logarithms"
// Advances in Cryptology - CRYPTO 2003.
// This header defines the class CamenischShoup, representing a key for the
// Camenisch Shoup cryptosystem. It can be initialized with or without the
// private (decryption) key.
// The class, once initialized, allows encryption and decryption of messages.
// The implementation here does not include the portion of the ciphertext,
// corresponding to non-malleability, as described in [CS'03].
//
// Example Usage:
//  Context ctx;
//  CamenischShoupKey key  = GenerateCamenischShoupKey(&ctx, n_length_bits, s,
//    vector_encryption_length);
//  PrivateCamenischShoup private_key(&ctx, key.n, key.s, key.g, key.xs,
//    key.ys);
//  CamenischShoupCiphertext ct = key.Encrypt(ms);

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_CAMENISCH_SHOUP_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_CAMENISCH_SHOUP_H_

#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/fixed_base_exp.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

struct CamenischShoupCiphertext {
  // For public key (g,ys,n), messages ms, and randomness r and power s:
  // u =  g^r mod n^(s+1)
  // es[i] =  (1+n)^ms[i] * ys[i]^r mod n^(s+1)
  BigNum u;
  std::vector<BigNum> es;
};

// Holds a single Camenisch-Shoup ciphertext, together with the randomness used
// to encrypt.
struct CamenischShoupCiphertextWithRand {
  CamenischShoupCiphertext ct;
  BigNum r;
};

// Returns a BigNum g that is a random (n^s)-th residue modulo
// n^(s+1). Computed as g = x^(2n^s) mod n^(s+1) for random x in Z_(n^(s+1)).
// Assumes that n is a product of 2 safe primes.
BigNum GetGeneratorForCamenischShoup(Context* ctx, const BigNum& n, uint64_t s);

struct CamenischShoupKey {
  BigNum p;                           // A safe prime.
  BigNum q;                           // A different safe prime.
  BigNum n;                           // p * q
  uint64_t s;                         // n^(s+1) is the modulus for the scheme.
  uint64_t vector_encryption_length;  // The number of ys and xs per ciphertext.
  BigNum g;                           // A random 2(n^s)-th residue mod n^(s+1).
  std::vector<BigNum> ys;             // ys[i] = g^xs[i] mod n^(s+1)
  // Each x in xs is a secret key, a random value between 0 and n, relatively
  // prime to n.
  std::vector<BigNum> xs;
};

struct CamenischShoupPublicKey {
  BigNum n;                           // p * q, for secret p and q.
  uint64_t s;                         // n^(s+1) is the modulus for the scheme.
  uint64_t vector_encryption_length;  // The number of ys and xs per ciphertext.
  BigNum g;                           // A random 2(n^s)-th residue mod n^(s+1).
  // ys[i] = g^xs[i] mod n^(s+1) for xs in the secret key
  std::vector<BigNum> ys;
};

struct CamenischShoupPrivateKey {
  // ys[i] = g^xs[i] mod n^(s+1) for all other values in the public key.
  std::vector<BigNum> xs;
};

// Generates a new key for the Camenisch-Shoup cryptosystem.
CamenischShoupKey GenerateCamenischShoupKey(Context* ctx, int n_length_bits,
                                            uint64_t s,
                                            uint64_t vector_encryption_length);

// Generates a new key pair for the Camenisch-Shoup cryptosystem. Assumes that
// the modulus n has been correctly generated elsewhere as the product of 2
// sufficiently long safe (or pseudo-safe) primes.
std::pair<std::unique_ptr<CamenischShoupPublicKey>,
          std::unique_ptr<CamenischShoupPrivateKey>>
GenerateCamenischShoupKeyPair(Context* ctx, const BigNum& n, uint64_t s,
                              uint64_t vector_encryption_length);

// Creates a proto from the PublicKey struct.
proto::CamenischShoupPublicKey CamenischShoupPublicKeyToProto(
    const CamenischShoupPublicKey& public_key);
// Parses PublicKey proto into a struct.
StatusOr<CamenischShoupPublicKey> ParseCamenischShoupPublicKeyProto(
    Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto);
// Creates a proto from the PrivateKey struct.
proto::CamenischShoupPrivateKey CamenischShoupPrivateKeyToProto(
    const CamenischShoupPrivateKey& private_key);
// Parses PrivateKey proto into a struct.
StatusOr<CamenischShoupPrivateKey> ParseCamenischShoupPrivateKeyProto(
    Context* ctx, const proto::CamenischShoupPrivateKey& private_key_proto);
// Creates a proto from the Ciphertext struct.
proto::CamenischShoupCiphertext CamenischShoupCiphertextToProto(
    const CamenischShoupCiphertext& ciphertext);

// The classes below implement the Camenisch-Shoup cryptosystem.
// Does not include features of [CS'03] corresponding to non-malleability of
// ciphertexts.

class PublicCamenischShoup {
 public:
  // Initializes a public key for the Camenisch-Shoup cryptosystem.
  // Accepts modulus n which is the product of safe primes p and q, a power s,
  // random n-th residue g modulo n^(s+1), and y = g^x for unknown x. Also
  // accepts a Context, of which it doesn't take ownership.
  PublicCamenischShoup(Context* ctx, const BigNum& n, uint64_t s,
                       const BigNum& g, std::vector<BigNum> ys);

  // Parses the key proto and creates a PublicCamenischShoup. Fails when
  // parsing fails.
  static StatusOr<std::unique_ptr<PublicCamenischShoup>> FromProto(
      Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto);

  // PublicCamenischShoup is neither copyable nor movable.
  PublicCamenischShoup(const PublicCamenischShoup&) = delete;
  PublicCamenischShoup& operator=(const PublicCamenischShoup&) = delete;
  PublicCamenischShoup(PublicCamenischShoup&&) = delete;
  PublicCamenischShoup& operator=(PublicCamenischShoup&&) = delete;
  ~PublicCamenischShoup() = default;

  // Encrypts a message as (u = g^r mod n^(s+1), es) where es[i] = ys[i]^r *
  // (1+n)^ms[i] mod n^(s+1)). If |ms| < |ys_|, the remaining messages are
  // implicitly 0.
  //
  // Returns INVALID_ARGUMENT if the message is not >= 0, or if |ms| is > |ys_|.
  StatusOr<CamenischShoupCiphertext> Encrypt(const std::vector<BigNum>& ms);

  // Encrypts a message as in Encrypt, and also returns the randomness used for
  // encryption.
  StatusOr<CamenischShoupCiphertextWithRand> EncryptAndGetRand(
      const std::vector<BigNum>& ms);

  // Encrypts a message as (u = g^r mod n^(s+1), v = y^r * (1+n)^m mod n^(s+1)),
  // using the randomness supplied. If |ms| < |ys_|, the remaining messages are
  // implicitly 0.
  //
  // Returns INVALID_ARGUMENT if the message or randomness is not >= 0, or if
  // |ms| is > |ys_|.
  StatusOr<CamenischShoupCiphertext> EncryptWithRand(
      const std::vector<BigNum>& ms, const BigNum& r);

  // Homomorphically adds two ciphertexts mod n^(s+1).
  CamenischShoupCiphertext Add(const CamenischShoupCiphertext& ct1,
                               const CamenischShoupCiphertext& ct2);

  // Homomorphically multiplies a ciphertexts with a given scalar mod n.
  CamenischShoupCiphertext Multiply(const CamenischShoupCiphertext& ct,
                                    const BigNum& scalar);

  // Parses a CamenischShoupCiphertext if it appears to be consistent with the
  // key.
  //
  // Fails with INVALID_ARGUMENT if the ciphertext does not match the modulus,
  // or has too many components.
  StatusOr<CamenischShoupCiphertext> ParseCiphertextProto(
      const proto::CamenischShoupCiphertext& ciphertext_proto);

  // Getters
  inline const BigNum& g() const { return g_; }                 // generator
  inline const std::vector<BigNum>& ys() const { return ys_; }  // public keys
  inline const BigNum& n() const { return n_; }
  inline uint64_t s() const { return s_; }
  inline uint64_t vector_encryption_length() const {
    return vector_encryption_length_;
  }
  inline const BigNum& modulus() const { return modulus_; }  // = n^(s+1)
  inline const BigNum& message_upper_bound() const { return n_to_s_; }
  inline const BigNum& randomness_upper_bound() const { return n_; }

 private:
  Context* const ctx_;
  const BigNum n_;
  const uint64_t s_;
  const uint64_t vector_encryption_length_;  // = |ys|.
  // Vector containing the n powers up to s+1 for faster computation.
  const std::vector<BigNum> powers_of_n_;
  // The vector holding values that are computed repeatedly when encrypting
  // arbitrary messages via computing the binomial expansion of (1+n)^message.
  // The binomial expansion of (1+n) to some arbitrary exponent has constant
  // factors depending on only 1, n, and s regardless of the exponent value,
  // this vector holds each of these fixed values for faster computation.
  // Refer to Section 4.2 "Optimization of Encryption" from the
  // Damgaard-Jurik-Nielsen paper for more information.
  const std::vector<BigNum> encryption_precomp_;
  const BigNum n_to_s_;
  const BigNum modulus_;  // equal to n^(s+1)
  const BigNum g_;
  const std::vector<BigNum> ys_;
  // For fast computation of g^r mod n^(s+1).
  const std::unique_ptr<FixedBaseExp> g_fbe_;
  // For fast computation of y^r mod n^(s+1).
  std::vector<std::unique_ptr<FixedBaseExp>> ys_fbe_;
};

class PrivateCamenischShoup {
 public:
  // Initializes a private key for the Camenisch-Shoup cryptosystem.
  // Accepts modulus n which is the product of safe primes p and q, a power s,
  // and a random n-th residue g modulo n^(s+1).
  // Also accepts x and y = g^x mod n^(s+1) for randomly selected x, where x
  // serves as the secret key. x should be randomly chosen between 0 and n and
  // relatively prime to n (i.e. x is in Z*n).
  // Also accepts a Context, of which it doesn't take ownership.
  // Returns a CHECK error if |ys| != |xs|.
  PrivateCamenischShoup(Context* ctx, const BigNum& n, uint64_t s,
                        const BigNum& g, std::vector<BigNum> ys,
                        std::vector<BigNum> xs);

  // Parses the key protos and creates a PrivateCamenischShoup. Fails when
  // parsing fails.
  static StatusOr<std::unique_ptr<PrivateCamenischShoup>> FromProto(
      Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto,
      const proto::CamenischShoupPrivateKey& private_key_proto);

  // PrivateCamenischShoup is neither copyable nor movable.
  PrivateCamenischShoup(const PrivateCamenischShoup&) = delete;
  PrivateCamenischShoup& operator=(const PrivateCamenischShoup&) = delete;
  PrivateCamenischShoup(PrivateCamenischShoup&&) = delete;
  PrivateCamenischShoup& operator=(PrivateCamenischShoup&&) = delete;
  ~PrivateCamenischShoup() = default;

  // Encrypts a message as (u = g^r mod n^2, v = y^r * (1+n)^m mod n^2). If |ms|
  // < |ys_|, the remaining messages are implicitly 0.
  //
  // Returns INVALID_ARGUMENT if some message is not >= 0, or if |ms| > |ys_|.
  StatusOr<CamenischShoupCiphertext> Encrypt(const std::vector<BigNum>& ms);

  // Encrypts a message as in Encrypt, and also returns the randomness used for
  // encryption.
  StatusOr<CamenischShoupCiphertextWithRand> EncryptAndGetRand(
      const std::vector<BigNum>& ms);

  // Encrypts a message as (u = g^r mod n^2, v = y^r * (1+n)^m mod n^2), using
  // the randomness supplied. If |ms| < |ys_|, the remaining messages are
  // implicitly 0.
  //
  // Returns INVALID_ARGUMENT if some message or the randomness not >= 0, or if
  // |ms| > |ys_|.
  StatusOr<CamenischShoupCiphertext> EncryptWithRand(
      const std::vector<BigNum>& ms, const BigNum& r);

  // Decrypts a given Camenisch-Shoup cipertext and returns the encrypted
  // message reduced mod n. Computes: ms such that (1+n)^ms[i] = (es[i] /
  // u^xs[i] mod n^(s+1)).
  //
  // Returns INVALID_ARGUMENT if the ciphertext is invalid/ cannot be decrypted.
  // Expects vector_encryption_length components in the ciphertext.
  StatusOr<std::vector<BigNum>> Decrypt(const CamenischShoupCiphertext& ct);

  // Parses a CamenischShoupCiphertext if it appears to be consistent with the
  // key.
  //
  // Fails with INVALID_ARGUMENT if the ciphertext does not match the modulus,
  // or has too many components.
  StatusOr<CamenischShoupCiphertext> ParseCiphertextProto(
      const proto::CamenischShoupCiphertext& ciphertext_proto);

  // Getters
  inline const BigNum& g() { return g_; }                 // generator
  inline const std::vector<BigNum>& ys() { return ys_; }  // public keys
  inline const std::vector<BigNum>& xs() { return xs_; }  // secret keys
  inline const BigNum& n() { return n_; }
  inline uint64_t s() { return s_; }
  inline const BigNum& modulus() { return modulus_; }
  inline uint64_t vector_encryption_length() {
    return vector_encryption_length_;
  }

 private:
  Context* const ctx_;
  const BigNum n_;
  const uint64_t s_;
  const uint64_t vector_encryption_length_;  // = |ys| = |xs|.
  // Vector containing the n powers up to s+1 for faster computation.
  const std::vector<BigNum> powers_of_n_;
  // The vector holding values that are computed repeatedly when encrypting
  // arbitrary messages via computing the binomial expansion of (1+n)^message.
  // The binomial expansion of (1+n) to some arbitrary exponent has constant
  // factors depending on only 1, n, and s regardless of the exponent value,
  // this vector holds each of these fixed values for faster computation.
  // Refer to Section 4.2 "Optimization of Encryption" from the
  // Damgaard-Jurik-Nielsen paper for more information.
  const std::vector<BigNum> encryption_precomp_;
  // Intermediate values used repeatedly in decryption.
  std::map<std::pair<int, int>, BigNum> decryption_precomp_;
  const BigNum n_to_s_;
  const BigNum modulus_;  // equal to n^(s+1)
  const BigNum g_;
  const std::vector<BigNum> ys_;
  const std::vector<BigNum> xs_;  // secret key
  std::unique_ptr<FixedBaseExp> g_fbe_;
  std::vector<std::unique_ptr<FixedBaseExp>> ys_fbe_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_CAMENISCH_SHOUP_H_
