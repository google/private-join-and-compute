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

#include "private_join_and_compute/crypto/paillier.h"

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "absl/container/node_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/fixed_base_exp.h"
#include "private_join_and_compute/crypto/two_modulus_crt.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

namespace {
// The number of times to iteratively try to find a generator for a safe prime
// starting from the candidate, 2.
constexpr int32_t kGeneratorTryCount = 1000;
}  // namespace

// A class representing a table of BigNums.
// The column length of the table is fixed and given in the constructor.
// Example:
//   // Given BigNum a;
//   BigNumTable table(5);
//   table.Insert(2, 3, a);
//   BigNum b = table.Get(2, 3)  // returns the same copy of BigNum a each time
//                               // Get is called with the same parameters.
//
// Note that while a two-dimensional vector can be used in place of this class,
// this is more versatile in the case of partially filled tables.
class BigNumTable {
 public:
  // Creates a BigNumTable with a fixed column length.
  explicit BigNumTable(size_t column_length)
      : column_length_(column_length), table_() {}

  // Inserts a copy of num into x, y cell of the table.
  void Insert(int x, int y, const BigNum& num) {
    CHECK_LT(y, column_length_);
    table_.insert(std::make_pair(x * column_length_ + y, num));
  }

  // Returns a reference to the BigNum at x, y cell.
  // Note that this object must outlive the scope of whoever called this
  // function so that the returned reference stays valid.
  const BigNum& Get(int x, int y) const {
    CHECK_LT(y, column_length_);
    auto iter = table_.find(x * column_length_ + y);
    if (iter == table_.end()) {
      LOG(FATAL) << "The element at x = " << x << " and y = " << y
                 << " does not exist";
    }
    return iter->second;
  }

 private:
  const size_t column_length_;
  absl::node_hash_map<int, BigNum> table_;
};

namespace {

// Returns a BigNum, g, that is a generator for the Zp*.
BigNum GetGeneratorForSafePrime(Context* ctx, const BigNum& p) {
  CHECK(p.IsSafePrime());
  BigNum q = (p - ctx->One()) / ctx->Two();
  BigNum g = ctx->CreateBigNum(2);
  for (int32_t i = 0; i < kGeneratorTryCount; i++) {
    if (g.ModSqr(p).IsOne() || g.ModExp(q, p).IsOne()) {
      g = g + ctx->One();
    } else {
      return g;
    }
  }
  // Just in case IsSafePrime is not correct.
  LOG(FATAL) << "Either try_count is insufficient or p is not a safe prime."
             << " generator_try_count: " << kGeneratorTryCount;
}

// Returns a BigNum, g, that is a generator for Zn*, where n is the product
// of 2 safe primes.
BigNum GetGeneratorForSafeModulus(Context* ctx, const BigNum& n) {
  // As explained in Damgard-Jurik-Nielsen, if n is the product of safe primes,
  // it is sufficient to choose a random number x in Z*n and return
  // g = -(x^2) mod n
  BigNum x = ctx->RelativelyPrimeRandomLessThan(n);
  return n - x.ModSqr(n);
}

// Returns a BigNum, g, that is a generator for Zp^t* for any t > 1.
BigNum GetGeneratorOfPrimePowersFromSafePrime(Context* ctx, const BigNum& p) {
  BigNum g = GetGeneratorForSafePrime(ctx, p);
  if (g.ModExp(p - ctx->One(), p * p).IsOne()) {
    return g + p;
  }
  return g;
}

// Returns a vector of num^i for i in [0, s + 1].
std::vector<BigNum> GetPowers(Context* ctx, const BigNum& num, int s) {
  std::vector<BigNum> powers;
  powers.push_back(ctx->CreateBigNum(1));
  for (int i = 1; i <= s + 1; i++) {
    powers.push_back(powers.back().Mul(num));
  }
  return powers;
}

// Returns a vector of (1 / (i!)) * n^i mod n^(s+1) for i in [0, s].
std::vector<BigNum> GetPrecomp(Context* ctx, const BigNum& num,
                               const BigNum& modulus, int s) {
  std::vector<BigNum> precomp;
  precomp.push_back(ctx->CreateBigNum(1));
  for (int i = 1; i <= s; i++) {
    BigNum i_inv = ctx->CreateBigNum(i).ModInverse(modulus).value();
    BigNum i_inv_n = i_inv.ModMul(num, modulus);
    precomp.push_back(precomp.back().ModMul(i_inv_n, modulus));
  }
  return precomp;
}

// Returns a vector of (1 / (k!)) * n^(k - 1) mod p^j for 2 <= k <= j <= s.
// Reuses the values from GetPrecomp function output, precomp.
std::unique_ptr<BigNumTable> GetDecryptPrecomp(
    Context* ctx, const std::vector<BigNum>& precomp,
    const std::vector<BigNum>& powers, int s) {
  // The first index is k and the second one is j from the Theorem 1 algorithm
  // of Damgaard-Jurik-Nielsen paper.
  // The table indices are [2, s] in each dimension with the following
  // structure:
  //     j
  //  +-----+
  //   -----|
  //    ----|  k
  //     ---|
  //      --|
  //       -+
  std::unique_ptr<BigNumTable> precomp_table(new BigNumTable(s + 1));
  for (int k = 2; k <= s; k++) {
    BigNum k_inverse = ctx->CreateBigNum(k).ModInverse(powers[s]).value();
    precomp_table->Insert(k, s, k_inverse.ModMul(precomp[k - 1], powers[s]));
    for (int j = s - 1; j >= k; j--) {
      precomp_table->Insert(k, j, precomp_table->Get(k, j + 1).Mod(powers[j]));
    }
  }
  return precomp_table;
}

// Computes (1 + powers[1])^message via binomial expansion (message=m):
// 1 + mn + C(m, 2)n^2 + ... + C(m, s)n^s mod n^(s + 1)
BigNum ComputeByBinomialExpansion(Context* ctx,
                                  const std::vector<BigNum>& precomp,
                                  const std::vector<BigNum>& powers,
                                  const BigNum& message) {
  // Refer to Section 4.2 Optimizations of Encryption from the Damgaard-Jurik
  // cryptosystem paper.
  BigNum c = ctx->CreateBigNum(1);
  BigNum tmp = ctx->CreateBigNum(1);
  const int s = precomp.size() - 1;
  BigNum reduced_message = message.Mod(powers[s]);
  for (int j = 1; j <= s; j++) {
    const BigNum& j_bn = ctx->CreateBigNum(j);
    if (reduced_message < j_bn) {
      break;
    }
    tmp = tmp.ModMul(reduced_message - j_bn + ctx->One(), powers[s - j + 1]);
    c = c + tmp.ModMul(precomp[j], powers[s + 1]);
  }
  return c;
}

}  // namespace

StatusOr<std::pair<PaillierPublicKey, PaillierPrivateKey>>
GeneratePaillierKeyPair(Context* ctx, int32_t modulus_length, int32_t s) {
  if (modulus_length / 2 <= 0 || s <= 0) {
    return InvalidArgumentError(
        "GeneratePaillierKeyPair: modulus_length/2 and s must each be >0");
  }

  BigNum p = ctx->GenerateSafePrime(modulus_length / 2);
  BigNum q = ctx->GenerateSafePrime(modulus_length / 2);
  while (p == q) {
    q = ctx->GenerateSafePrime(modulus_length / 2);
  }
  BigNum n = p * q;

  PaillierPrivateKey private_key;
  private_key.set_p(p.ToBytes());
  private_key.set_q(q.ToBytes());
  private_key.set_s(s);

  PaillierPublicKey public_key;
  public_key.set_n(n.ToBytes());
  public_key.set_s(s);

  return std::make_pair(std::move(public_key), std::move(private_key));
}

// A helper class defining Encrypt and Decrypt for only one of the prime parts
// of the composite number n. Computing (1+n)^m * g^r mod p^(s+1) where r is in
// [1, p) for both p and q and then computing CRT yields a result with the same
// randomness as computing (1+n)^m * random^(n^s) mod n^(s+1) whereas the former
// is much faster as the modulus length is half the size of n for each step.
//
// This class is not thread-safe since Context is not thread-safe.
// Note that this does *not* take the ownership of Context.
class PrimeCrypto {
 public:
  // Creates a PrimeCrypto with the given parameter where p and other_prime is
  // either <p, q> or <q, p>.
  PrimeCrypto(Context* ctx, const BigNum& p, const BigNum& other_prime, int s)
      : ctx_(ctx),
        p_(p),
        p_phi_(p - ctx->One()),
        n_(p * other_prime),
        s_(s),
        powers_(GetPowers(ctx, p, s)),
        precomp_(GetPrecomp(ctx, n_, powers_[s + 1], s)),
        lambda_inv_(p_phi_.ModInverse(powers_[s_]).value()),
        other_prime_inv_(other_prime.ModInverse(powers_[s]).value()),
        decrypt_precomp_(GetDecryptPrecomp(ctx, precomp_, powers_, s)),
        g_p_(GetGeneratorOfPrimePowersFromSafePrime(ctx, p)),
        fbe_(FixedBaseExp::GetFixedBaseExp(
            ctx, g_p_.ModExp(n_.Exp(ctx->CreateBigNum(s)), powers_[s + 1]),
            powers_[s + 1])) {}

  // PrimeCrypto is neither copyable nor movable.
  PrimeCrypto(const PrimeCrypto&) = delete;
  PrimeCrypto& operator=(const PrimeCrypto&) = delete;

  // Computes (1+n)^m * g^r mod p^(s+1) where r is in [1, p).
  StatusOr<BigNum> Encrypt(const BigNum& m) const {
    return EncryptWithRand(m, ctx_->GenerateRandBetween(ctx_->One(), p_));
  }

  // Encrypts the message similar to other Encrypt method, but uses the input
  // random value. (The caller has responsibility to ensure the randomness of
  // the value.)
  StatusOr<BigNum> EncryptWithRand(const BigNum& m, const BigNum& r) const {
    BigNum c_p = ComputeByBinomialExpansion(ctx_, precomp_, powers_, m);
    ASSIGN_OR_RETURN(BigNum g_to_r, fbe_->ModExp(r));
    return c_p.ModMul(g_to_r, powers_[s_ + 1]);
  }

  // Decrypts c for this prime part so that computing CRT with the other prime
  // decryption yields to the original message inside this ciphertext.
  BigNum Decrypt(const BigNum& c) const {
    // Theorem 1 algorithm from Damgaard-Jurik-Nielsen paper.
    // Cancels out the random portion and compute the L function.
    BigNum l_u = LFunc(c.ModExp(p_phi_, powers_[s_ + 1]));
    BigNum m_lambda = ctx_->CreateBigNum(0);
    for (int j = 1; j <= s_; j++) {
      BigNum t1 = l_u.Mod(powers_[j]);
      BigNum t2 = m_lambda;
      for (int k = 2; k <= j; k++) {
        m_lambda = m_lambda - ctx_->One();
        t2 = t2.ModMul(m_lambda, powers_[j]);
        t1 = t1 - t2 * decrypt_precomp_->Get(k, j);
      }
      m_lambda = std::move(t1);
    }
    return m_lambda.ModMul(lambda_inv_, powers_[s_]);
  }

  // Returns p^i from the cache.
  const BigNum& GetPToExp(int i) const { return powers_[i]; }

 private:
  friend class PrimeCryptoWithRand;
  // Paillier L function modified to work on prime parts. Refer to the
  // subsection "Decryption" under Section 4.2 "Optimizations of Encryption"
  // from the Damgaard-Jurik cryptosystem paper.
  BigNum LFunc(const BigNum& c_mod_p_to_s_plus_one) const {
    return ((c_mod_p_to_s_plus_one - ctx_->One()) / p_)
        .ModMul(other_prime_inv_, GetPToExp(s_));
  }

  Context* const ctx_;
  const BigNum p_;
  const BigNum p_phi_;
  const BigNum n_;
  const int s_;
  const std::vector<BigNum> powers_;
  const std::vector<BigNum> precomp_;
  const BigNum lambda_inv_;
  const BigNum other_prime_inv_;
  const std::unique_ptr<BigNumTable> decrypt_precomp_;
  const BigNum g_p_;
  std::unique_ptr<FixedBaseExp> fbe_;
};

// Class that wraps a PrimeCrypto, and additionally can return the random number
// (used in an encryption) with the ciphertext.
class PrimeCryptoWithRand {
 public:
  explicit PrimeCryptoWithRand(PrimeCrypto* prime_crypto)
      : ctx_(prime_crypto->ctx_),
        prime_crypto_(prime_crypto),
        exp_for_report_(FixedBaseExp::GetFixedBaseExp(
            ctx_, prime_crypto_->g_p_,
            prime_crypto_->GetPToExp(prime_crypto_->s_ + 1))) {}

  // PrimeCryptoWithRand is neither copyable nor movable.
  PrimeCryptoWithRand(const PrimeCryptoWithRand&) = delete;
  PrimeCryptoWithRand& operator=(const PrimeCryptoWithRand&) = delete;

  // Encrypts the message and returns the result the same way as in PrimeCrypto.
  StatusOr<BigNum> Encrypt(const BigNum& m) const {
    return prime_crypto_->Encrypt(m);
  }

  // Encrypts the message with the input random value the same way as in
  // PrimeCrypto.
  StatusOr<BigNum> EncryptWithRand(const BigNum& m, const BigNum& r) const {
    return prime_crypto_->EncryptWithRand(m, r);
  }

  // Encrypts the message the same way as in PrimeCrypto, and returns the
  // random used.
  StatusOr<PaillierEncAndRand> EncryptAndGetRand(const BigNum& m) const {
    BigNum r = ctx_->GenerateRandBetween(ctx_->One(), prime_crypto_->p_);
    ASSIGN_OR_RETURN(BigNum ct, EncryptWithRand(m, r));
    ASSIGN_OR_RETURN(BigNum exp_for_report_to_r, exp_for_report_->ModExp(r));
    return {{std::move(ct), std::move(exp_for_report_to_r)}};
  }

  // Decrypts the ciphertext the same way as in PrimeCrypto.
  BigNum Decrypt(const BigNum& c) const { return prime_crypto_->Decrypt(c); }

 private:
  Context* const ctx_;
  const PrimeCrypto* const prime_crypto_;
  std::unique_ptr<FixedBaseExp> exp_for_report_;
};

static const int kDefaultS = 1;

PublicPaillier::PublicPaillier(Context* ctx, const BigNum& n, int s)
    : ctx_(ctx),
      n_(n),
      s_(s),
      n_powers_(GetPowers(ctx, n_, s)),
      modulus_(n_powers_.back()),
      g_n_fbe_(FixedBaseExp::GetFixedBaseExp(
          ctx,
          GetGeneratorForSafeModulus(ctx_, n).ModExp(n_powers_[s], modulus_),
          modulus_)),
      precomp_(GetPrecomp(ctx, n_, modulus_, s)) {}

PublicPaillier::PublicPaillier(Context* ctx, const BigNum& n)
    : PublicPaillier(ctx, n, kDefaultS) {}

PublicPaillier::PublicPaillier(Context* ctx,
                               const PaillierPublicKey& public_key_proto)
    : PublicPaillier(ctx, ctx->CreateBigNum(public_key_proto.n()),
                     public_key_proto.s()) {}

PublicPaillier::~PublicPaillier() = default;

BigNum PublicPaillier::Add(const BigNum& ciphertext1,
                           const BigNum& ciphertext2) const {
  return ciphertext1.ModMul(ciphertext2, modulus_);
}

BigNum PublicPaillier::Multiply(const BigNum& c, const BigNum& m) const {
  return c.ModExp(m, modulus_);
}

BigNum PublicPaillier::LeftShift(const BigNum& c, int shift_amount) const {
  return Multiply(c, ctx_->One().Lshift(shift_amount));
}

StatusOr<BigNum> PublicPaillier::Encrypt(const BigNum& m) const {
  if (!m.IsNonNegative()) {
    return InvalidArgumentError(
        "PublicPaillier::Encrypt() - Cannot encrypt negative number.");
  }
  if (m >= n_powers_[s_]) {
    return InvalidArgumentError(
        "PublicPaillier::Encrypt() - Message not smaller than n^s.");
  }
  return EncryptUsingGeneratorAndRand(m, ctx_->GenerateRandLessThan(n_));
}

StatusOr<BigNum> PublicPaillier::EncryptUsingGeneratorAndRand(
    const BigNum& m, const BigNum& r) const {
  if (r > n_) {
    return InvalidArgumentError(
        "PublicPaillier: The given random is not less than or equal to n.");
  }
  BigNum c = ComputeByBinomialExpansion(ctx_, precomp_, n_powers_, m);
  ASSIGN_OR_RETURN(BigNum g_n_to_r, g_n_fbe_->ModExp(r));
  return c.ModMul(g_n_to_r, modulus_);
}

StatusOr<BigNum> PublicPaillier::EncryptWithRand(const BigNum& m,
                                                 const BigNum& r) const {
  if (r.Gcd(n_) != ctx_->One()) {
    return InvalidArgumentError(
        "PublicPaillier::EncryptWithRand: The given random is not in Z*n.");
  }
  BigNum c = ComputeByBinomialExpansion(ctx_, precomp_, n_powers_, m);
  return c.ModMul(r.ModExp(n_powers_[s_], modulus_), modulus_);
}

StatusOr<PaillierEncAndRand> PublicPaillier::EncryptAndGetRand(
    const BigNum& m) const {
  BigNum r = ctx_->RelativelyPrimeRandomLessThan(n_);
  ASSIGN_OR_RETURN(BigNum c, EncryptWithRand(m, r));
  return {{std::move(c), std::move(r)}};
}

PrivatePaillier::~PrivatePaillier() = default;

PrivatePaillier::PrivatePaillier(Context* ctx, const BigNum& p, const BigNum& q,
                                 int s)
    : ctx_(ctx),
      n_to_s_((p * q).Exp(ctx_->CreateBigNum(s))),
      n_to_s_plus_one_(n_to_s_ * p * q),
      p_crypto_(new PrimeCrypto(ctx, p, q, s)),
      q_crypto_(new PrimeCrypto(ctx, q, p, s)),
      two_mod_crt_encrypt_(new TwoModulusCrt(p_crypto_->GetPToExp(s + 1),
                                             q_crypto_->GetPToExp(s + 1))),
      two_mod_crt_decrypt_(new TwoModulusCrt(p_crypto_->GetPToExp(s),
                                             q_crypto_->GetPToExp(s))) {}

PrivatePaillier::PrivatePaillier(Context* ctx,
                                 const PaillierPrivateKey& private_key_proto)
    : PrivatePaillier(ctx, ctx->CreateBigNum(private_key_proto.p()),
                      ctx->CreateBigNum(private_key_proto.q()),
                      private_key_proto.s()) {}

StatusOr<BigNum> PrivatePaillier::Encrypt(const BigNum& m) const {
  if (!m.IsNonNegative()) {
    return InvalidArgumentError(
        "PrivatePaillier::Encrypt() - Cannot encrypt negative number.");
  }
  if (m >= n_to_s_) {
    return InvalidArgumentError(
        "PrivatePaillier::Encrypt() - Message not smaller than n^s.");
  }
  ASSIGN_OR_RETURN(BigNum p_ct, p_crypto_->Encrypt(m));
  ASSIGN_OR_RETURN(BigNum q_ct, q_crypto_->Encrypt(m));
  return two_mod_crt_encrypt_->Compute(p_ct, q_ct);
}

PrivatePaillier::PrivatePaillier(Context* ctx, const BigNum& p, const BigNum& q)
    : PrivatePaillier(ctx, p, q, kDefaultS) {}

StatusOr<BigNum> PrivatePaillier::Decrypt(const BigNum& c) const {
  if (!c.IsNonNegative()) {
    return InvalidArgumentError(
        "PrivatePaillier::Decrypt() - Cannot decrypt negative number.");
  }
  if (c >= n_to_s_plus_one_) {
    return InvalidArgumentError(
        "PrivatePaillier::Decrypt() - Ciphertext not smaller than n^(s+1).");
  }
  return two_mod_crt_decrypt_->Compute(p_crypto_->Decrypt(c),
                                       q_crypto_->Decrypt(c));
}

PrivatePaillierWithRand::PrivatePaillierWithRand(
    PrivatePaillier* private_paillier)
    : ctx_(private_paillier->ctx_), private_paillier_(private_paillier) {
  const BigNum& p = private_paillier_->p_crypto_->GetPToExp(1);
  const BigNum& q = private_paillier_->q_crypto_->GetPToExp(1);
  two_mod_crt_rand_ = std::make_unique<TwoModulusCrt>(p, q);
  p_crypto_ =
      std::make_unique<PrimeCryptoWithRand>(private_paillier_->p_crypto_.get());
  q_crypto_ =
      std::make_unique<PrimeCryptoWithRand>(private_paillier_->q_crypto_.get());
}

PrivatePaillierWithRand::~PrivatePaillierWithRand() = default;

StatusOr<BigNum> PrivatePaillierWithRand::Encrypt(const BigNum& m) const {
  return private_paillier_->Encrypt(m);
}

StatusOr<PaillierEncAndRand> PrivatePaillierWithRand::EncryptAndGetRand(
    const BigNum& m) const {
  if (!m.IsNonNegative()) {
    return InvalidArgumentError(
        "PrivatePaillier::Encrypt() - Cannot encrypt negative number.");
  }
  if (m >= private_paillier_->n_to_s_) {
    return InvalidArgumentError(
        "PrivatePaillier::Encrypt() - Message not smaller than n^s.");
  }

  ASSIGN_OR_RETURN(const PaillierEncAndRand enc_p,
                   p_crypto_->EncryptAndGetRand(m));
  ASSIGN_OR_RETURN(const PaillierEncAndRand enc_q,
                   q_crypto_->EncryptAndGetRand(m));

  BigNum c = private_paillier_->two_mod_crt_encrypt_->Compute(enc_p.ciphertext,
                                                              enc_q.ciphertext);
  BigNum r = two_mod_crt_rand_->Compute(enc_p.rand, enc_q.rand);
  return {{std::move(c), std::move(r)}};
}

StatusOr<BigNum> PrivatePaillierWithRand::Decrypt(const BigNum& c) const {
  return private_paillier_->Decrypt(c);
}

}  // namespace private_join_and_compute
