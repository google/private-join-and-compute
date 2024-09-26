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

#include "private_join_and_compute/crypto/camenisch_shoup.h"

#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

namespace {

// Returns a vector of (1 / (i!)) * n^i mod n^(s+1) for i in [0, s]. Modulus
// should be n^(s+1).
std::vector<BigNum> GetPrecomp(Context* ctx, const BigNum& n,
                               const BigNum& modulus, uint64_t s) {
  std::vector<BigNum> precomp;
  precomp.push_back(ctx->CreateBigNum(1));
  for (uint64_t i = 1; i <= s; i++) {
    BigNum i_inv = ctx->CreateBigNum(i).ModInverse(modulus).value();
    BigNum i_inv_n = i_inv.ModMul(n, modulus);
    precomp.push_back(precomp.back().ModMul(i_inv_n, modulus));
  }
  return precomp;
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

// Returns a table of (1 / (k!)) * n^(k - 1) mod n^j for 2 <= k <= j <= s.
// Reuses the values from GetPrecomp function output, precomp. The result is a
// table that maps (k,j) to the BigNum (1 / (k!)) * n^(k - 1) mod n^j, for all
// (k,j) with 2 <= k <= j <= s
std::map<std::pair<int, int>, BigNum> GetDecryptPrecomp(
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
  std::map<std::pair<int, int>, BigNum> precomp_table;
  for (int k = 2; k <= s; k++) {
    BigNum k_inverse = ctx->CreateBigNum(k).ModInverse(powers[s]).value();
    precomp_table.insert(
        {std::make_pair(k, s), k_inverse.ModMul(precomp[k - 1], powers[s])});
    for (int j = s - 1; j >= k; j--) {
      precomp_table.insert(
          {std::make_pair(k, j),
           precomp_table.at(std::make_pair(k, j + 1)).Mod(powers[j])});
    }
  }
  return precomp_table;
}

// Computes (1 + powers[1])^message via binomial expansion (message=m):
// 1 + mn + C(m, 2)n^2 + ... + C(m, s)n^s mod n^(s + 1).
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

StatusOr<CamenischShoupCiphertext> CommonEncryptWithRand(
    Context* ctx, const std::vector<BigNum>& ms, const BigNum& r,
    const BigNum& n, const BigNum& n_to_s, const std::vector<BigNum>& precomp,
    const std::vector<BigNum>& powers, const FixedBaseExp* g_fbe,
    const std::vector<std::unique_ptr<FixedBaseExp>>& ys_fbe,
    const BigNum& modulus) {
  if (ms.size() > ys_fbe.size()) {
    return InvalidArgumentError(absl::StrCat(
        "CamenischShoup::EncryptWithRand: Too many messages: max = ",
        ys_fbe.size(), ", given = ", ms.size()));
  }
  if (!r.IsNonNegative() || (!r.Gcd(n).IsOne() && !r.IsZero())) {
    return InvalidArgumentError(
        "CamenischShoup::EncryptWithRand() - r must be >=0 and "
        "not share prime factors with n.");
  }

  ASSIGN_OR_RETURN(BigNum u, g_fbe->ModExp(r));

  std::vector<BigNum> es;
  es.reserve(ys_fbe.size());
  for (size_t i = 0; i < ys_fbe.size(); i++) {
    ASSIGN_OR_RETURN(BigNum y_to_r, ys_fbe[i]->ModExp(r));
    if (i < ms.size()) {
      BigNum one_plus_n_to_m =
          ComputeByBinomialExpansion(ctx, precomp, powers, ms[i]);
      BigNum e = (y_to_r * one_plus_n_to_m).Mod(modulus);
      es.push_back(e);
    } else {
      // Implicitly encrypt 0 if |ms| < |ys|.
      es.push_back(y_to_r);
    }
  }
  return {{std::move(u), std::move(es)}};
}

StatusOr<CamenischShoupCiphertextWithRand> CommonEncryptAndGetRand(
    Context* ctx, const std::vector<BigNum>& ms, const BigNum& n,
    const BigNum& n_to_s, const std::vector<BigNum>& precomp,
    const std::vector<BigNum>& powers, const FixedBaseExp* g_fbe,
    const std::vector<std::unique_ptr<FixedBaseExp>>& ys_fbe,
    const BigNum& modulus) {
  for (const BigNum& m : ms) {
    if (!m.IsNonNegative()) {
      return InvalidArgumentError(
          "CamenischShoup::EncryptAndGetRand() - Cannot encrypt negative "
          "number.");
    }
  }

  BigNum r = ctx->RelativelyPrimeRandomLessThan(n);
  ASSIGN_OR_RETURN(CamenischShoupCiphertext ct,
                   CommonEncryptWithRand(ctx, ms, r, n, n_to_s, precomp, powers,
                                         g_fbe, ys_fbe, modulus));

  return {{std::move(ct), std::move(r)}};
}

StatusOr<CamenischShoupCiphertext> CommonEncrypt(
    Context* ctx, const std::vector<BigNum>& ms, const BigNum& n,
    const BigNum& n_to_s, const std::vector<BigNum>& precomp,
    const std::vector<BigNum>& powers, const FixedBaseExp* g_fbe,
    const std::vector<std::unique_ptr<FixedBaseExp>>& ys_fbe,
    const BigNum& modulus) {
  ASSIGN_OR_RETURN(auto encryption_and_randomness,
                   CommonEncryptAndGetRand(ctx, ms, n, n_to_s, precomp, powers,
                                           g_fbe, ys_fbe, modulus));
  return {std::move(encryption_and_randomness.ct)};
}

// A common helper: generates a key with a pre-specified modulus. The fields "p"
// and "q" are "0" in the returned key.
CamenischShoupKey GenerateCamenischShoupKeyBase(
    Context* ctx, const BigNum& n, uint64_t s,
    uint64_t vector_encryption_length) {
  BigNum g = GetGeneratorForCamenischShoup(ctx, n, s);

  std::vector<BigNum> xs;
  std::vector<BigNum> ys;
  xs.reserve(vector_encryption_length);
  ys.reserve(vector_encryption_length);
  for (uint64_t i = 0; i < vector_encryption_length; i++) {
    BigNum x = ctx->RelativelyPrimeRandomLessThan(n);
    BigNum y = g.ModExp(x, n.Exp(ctx->CreateBigNum(s + 1)));
    xs.emplace_back(std::move(x));
    ys.emplace_back(std::move(y));
  }

  return CamenischShoupKey{
      ctx->Zero(),   ctx->Zero(),  n, s, vector_encryption_length, std::move(g),
      std::move(ys), std::move(xs)};
}

StatusOr<CamenischShoupCiphertext> CommonParseCiphertextProto(
    Context* ctx, const BigNum& modulus, uint64_t vector_encryption_length,
    const proto::CamenischShoupCiphertext& ct_proto) {
  BigNum u = ctx->CreateBigNum(ct_proto.u());
  std::vector<BigNum> es = ParseBigNumVectorProto(ctx, ct_proto.es());
  if (u >= modulus || !u.IsNonNegative()) {
    return absl::InvalidArgumentError(
        "CommonParseCiphertextProto: u must be in [0, modulus).");
  }
  if (es.size() > vector_encryption_length) {
    return absl::InvalidArgumentError(
        "CommonParseCiphertextProto: es has too many components.");
  }
  for (const BigNum& es_component : es) {
    if (es_component >= modulus || !es_component.IsNonNegative()) {
      return absl::InvalidArgumentError(
          "CommonParseCiphertextProto: some element of es is not in [0, "
          "modulus).");
    }
  }
  return CamenischShoupCiphertext{std::move(u), std::move(es)};
}

}  // namespace

BigNum GetGeneratorForCamenischShoup(Context* ctx, const BigNum& n,
                                     uint64_t s) {
  BigNum n_to_s = n.Exp(ctx->CreateBigNum(s));
  BigNum n_to_s_plus_1 = n.Exp(ctx->CreateBigNum(s + 1));
  BigNum x = ctx->RelativelyPrimeRandomLessThan(n_to_s_plus_1);
  return x.ModExp((ctx->Two() * n_to_s), n_to_s_plus_1);
}

CamenischShoupKey GenerateCamenischShoupKey(Context* ctx, int n_length_bits,
                                            uint64_t s,
                                            uint64_t vector_encryption_length) {
  BigNum p = ctx->GenerateSafePrime(n_length_bits / 2);
  BigNum q = ctx->GenerateSafePrime(n_length_bits / 2);
  while (p == q) {
    q = ctx->GenerateSafePrime(n_length_bits / 2);
  }
  BigNum n = p * q;
  CamenischShoupKey key =
      GenerateCamenischShoupKeyBase(ctx, n, s, vector_encryption_length);
  key.p = std::move(p);
  key.q = std::move(q);
  return key;
}

std::pair<std::unique_ptr<CamenischShoupPublicKey>,
          std::unique_ptr<CamenischShoupPrivateKey>>
GenerateCamenischShoupKeyPair(Context* ctx, const BigNum& n, uint64_t s,
                              uint64_t vector_encryption_length) {
  CamenischShoupKey cs_key =
      GenerateCamenischShoupKeyBase(ctx, n, s, vector_encryption_length);

  auto public_key =
      std::make_unique<CamenischShoupPublicKey>(CamenischShoupPublicKey{
          std::move(cs_key.n), cs_key.s, cs_key.vector_encryption_length,
          std::move(cs_key.g), std::move(cs_key.ys)});
  auto private_key = std::make_unique<CamenischShoupPrivateKey>(
      CamenischShoupPrivateKey{std::move(cs_key.xs)});

  return std::make_pair(std::move(public_key), std::move(private_key));
}

// Creates a proto from the PublicKey struct.
proto::CamenischShoupPublicKey CamenischShoupPublicKeyToProto(
    const CamenischShoupPublicKey& public_key) {
  proto::CamenischShoupPublicKey public_key_proto;
  public_key_proto.set_n(public_key.n.ToBytes());
  public_key_proto.set_g(public_key.g.ToBytes());
  *public_key_proto.mutable_ys() = BigNumVectorToProto(public_key.ys);
  public_key_proto.set_s(public_key.s);
  return public_key_proto;
}

StatusOr<CamenischShoupPublicKey> ParseCamenischShoupPublicKeyProto(
    Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto) {
  BigNum n = ctx->CreateBigNum(public_key_proto.n());
  if (n <= ctx->Zero()) {
    return absl::InvalidArgumentError(
        "FromProto: CamenischShoupPublicKey has n that's <= 0");
  }
  uint64_t s = public_key_proto.s();
  if (s == 0) {
    return absl::InvalidArgumentError(
        "FromProto: CamenischShoupPublicKey has s = 0");
  }
  BigNum modulus = n.Exp(ctx->CreateBigNum(s + 1));
  BigNum g = ctx->CreateBigNum(public_key_proto.g());
  if (g <= ctx->Zero() || g >= modulus || g.Gcd(n) != ctx->One()) {
    return absl::InvalidArgumentError(
        "FromProto: CamenischShoupPublicKey has invalid g");
  }
  std::vector<BigNum> ys = ParseBigNumVectorProto(ctx, public_key_proto.ys());
  uint64_t vector_encryption_length = ys.size();
  if (ys.empty()) {
    return absl::InvalidArgumentError(
        "FromProto: CamenischShoupPublicKey has empty ys");
  }
  for (const BigNum& y : ys) {
    if (y <= ctx->Zero() || y >= modulus || y.Gcd(n) != ctx->One()) {
      return absl::InvalidArgumentError(
          "FromProto: CamenischShoupPublicKey has invalid component in ys");
    }
  }
  return CamenischShoupPublicKey{std::move(n), s, vector_encryption_length,
                                 std::move(g), std::move(ys)};
}

// Creates a proto from the PrivateKey struct.
proto::CamenischShoupPrivateKey CamenischShoupPrivateKeyToProto(
    const CamenischShoupPrivateKey& private_key) {
  proto::CamenischShoupPrivateKey private_key_proto;
  *private_key_proto.mutable_xs() = BigNumVectorToProto(private_key.xs);
  return private_key_proto;
}

StatusOr<CamenischShoupPrivateKey> ParseCamenischShoupPrivateKeyProto(
    Context* ctx, const proto::CamenischShoupPrivateKey& private_key_proto) {
  std::vector<BigNum> xs = ParseBigNumVectorProto(ctx, private_key_proto.xs());
  return CamenischShoupPrivateKey{std::move(xs)};
}

// Creates a proto from the Ciphertext struct.
proto::CamenischShoupCiphertext CamenischShoupCiphertextToProto(
    const CamenischShoupCiphertext& ciphertext) {
  proto::CamenischShoupCiphertext ciphertext_proto;
  ciphertext_proto.set_u(ciphertext.u.ToBytes());
  *ciphertext_proto.mutable_es() = BigNumVectorToProto(ciphertext.es);
  return ciphertext_proto;
}

PublicCamenischShoup::PublicCamenischShoup(Context* ctx, const BigNum& n,
                                           uint64_t s, const BigNum& g,
                                           std::vector<BigNum> ys)
    : ctx_(ctx),
      n_(n),
      s_(s),
      vector_encryption_length_(ys.size()),
      powers_of_n_(GetPowers(ctx, n_, s_)),
      encryption_precomp_(GetPrecomp(ctx, n_, powers_of_n_[s + 1], s)),
      n_to_s_(powers_of_n_[s]),
      modulus_(powers_of_n_[s + 1]),
      g_(g),
      ys_(std::move(ys)),
      g_fbe_(FixedBaseExp::GetFixedBaseExp(ctx_, g_, modulus_)) {
  ys_fbe_.reserve(ys_.size());
  for (const BigNum& y : ys_) {
    ys_fbe_.push_back(FixedBaseExp::GetFixedBaseExp(ctx_, y, modulus_));
  }
}

StatusOr<std::unique_ptr<PublicCamenischShoup>> PublicCamenischShoup::FromProto(
    Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto) {
  ASSIGN_OR_RETURN(CamenischShoupPublicKey public_key,
                   ParseCamenischShoupPublicKeyProto(ctx, public_key_proto));
  return std::make_unique<PublicCamenischShoup>(ctx, public_key.n, public_key.s,
                                                public_key.g, public_key.ys);
}

StatusOr<CamenischShoupCiphertext> PublicCamenischShoup::Encrypt(
    const std::vector<BigNum>& ms) {
  return CommonEncrypt(ctx_, ms, n_, n_to_s_, encryption_precomp_, powers_of_n_,
                       g_fbe_.get(), ys_fbe_, modulus_);
}

StatusOr<CamenischShoupCiphertextWithRand>
PublicCamenischShoup::EncryptAndGetRand(const std::vector<BigNum>& ms) {
  return CommonEncryptAndGetRand(ctx_, ms, n_, n_to_s_, encryption_precomp_,
                                 powers_of_n_, g_fbe_.get(), ys_fbe_, modulus_);
}

StatusOr<CamenischShoupCiphertext> PublicCamenischShoup::EncryptWithRand(
    const std::vector<BigNum>& ms, const BigNum& r) {
  return CommonEncryptWithRand(ctx_, ms, r, n_, n_to_s_, encryption_precomp_,
                               powers_of_n_, g_fbe_.get(), ys_fbe_, modulus_);
}

CamenischShoupCiphertext PublicCamenischShoup::Add(
    const CamenischShoupCiphertext& ct1, const CamenischShoupCiphertext& ct2) {
  CHECK(ct1.es.size() == ct2.es.size());
  CHECK(ct1.es.size() == vector_encryption_length_);
  BigNum u = ct1.u.ModMul(ct2.u, modulus_);
  std::vector<BigNum> es;
  es.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    es.push_back(ct1.es[i].ModMul(ct2.es[i], modulus_));
  }
  return {std::move(u), std::move(es)};
}

CamenischShoupCiphertext PublicCamenischShoup::Multiply(
    const CamenischShoupCiphertext& ct, const BigNum& scalar) {
  BigNum u = ct.u.ModExp(scalar, modulus_);
  std::vector<BigNum> es;
  es.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    es.push_back(ct.es[i].ModExp(scalar, modulus_));
  }
  return {std::move(u), std::move(es)};
}

StatusOr<CamenischShoupCiphertext> PublicCamenischShoup::ParseCiphertextProto(
    const proto::CamenischShoupCiphertext& ciphertext_proto) {
  return CommonParseCiphertextProto(ctx_, modulus_, vector_encryption_length_,
                                    ciphertext_proto);
}

PrivateCamenischShoup::PrivateCamenischShoup(Context* ctx, const BigNum& n,
                                             uint64_t s, const BigNum& g,
                                             std::vector<BigNum> ys,
                                             std::vector<BigNum> xs)
    : ctx_(ctx),
      n_(n),
      s_(s),
      vector_encryption_length_(ys.size()),
      powers_of_n_(GetPowers(ctx, n_, s_)),
      encryption_precomp_(GetPrecomp(ctx, n_, powers_of_n_[s + 1], s)),
      decryption_precomp_(
          GetDecryptPrecomp(ctx, encryption_precomp_, powers_of_n_, s)),
      n_to_s_(powers_of_n_[s]),
      modulus_(powers_of_n_[s + 1]),
      g_(g),
      ys_(std::move(ys)),
      xs_(std::move(xs)),
      g_fbe_(FixedBaseExp::GetFixedBaseExp(ctx_, g_, modulus_)) {
  CHECK_EQ(ys_.size(), xs_.size());
  ys_fbe_.reserve(ys_.size());
  for (const BigNum& y : ys_) {
    ys_fbe_.push_back(FixedBaseExp::GetFixedBaseExp(ctx_, y, modulus_));
  }
}

StatusOr<std::unique_ptr<PrivateCamenischShoup>>
PrivateCamenischShoup::FromProto(
    Context* ctx, const proto::CamenischShoupPublicKey& public_key_proto,
    const proto::CamenischShoupPrivateKey& private_key_proto) {
  ASSIGN_OR_RETURN(CamenischShoupPublicKey public_key,
                   ParseCamenischShoupPublicKeyProto(ctx, public_key_proto));
  ASSIGN_OR_RETURN(CamenischShoupPrivateKey private_key,
                   ParseCamenischShoupPrivateKeyProto(ctx, private_key_proto));
  return std::make_unique<PrivateCamenischShoup>(ctx, public_key.n,
                                                 public_key.s, public_key.g,
                                                 public_key.ys, private_key.xs);
}

StatusOr<CamenischShoupCiphertext> PrivateCamenischShoup::Encrypt(
    const std::vector<BigNum>& ms) {
  return CommonEncrypt(ctx_, ms, n_, n_to_s_, encryption_precomp_, powers_of_n_,
                       g_fbe_.get(), ys_fbe_, modulus_);
}

StatusOr<CamenischShoupCiphertextWithRand>
PrivateCamenischShoup::EncryptAndGetRand(const std::vector<BigNum>& ms) {
  return CommonEncryptAndGetRand(ctx_, ms, n_, n_to_s_, encryption_precomp_,
                                 powers_of_n_, g_fbe_.get(), ys_fbe_, modulus_);
}

StatusOr<CamenischShoupCiphertext> PrivateCamenischShoup::EncryptWithRand(
    const std::vector<BigNum>& ms, const BigNum& r) {
  return CommonEncryptWithRand(ctx_, ms, r, n_, n_to_s_, encryption_precomp_,
                               powers_of_n_, g_fbe_.get(), ys_fbe_, modulus_);
}

StatusOr<std::vector<BigNum>> PrivateCamenischShoup::Decrypt(
    const CamenischShoupCiphertext& ct) {
  if (ct.es.size() != vector_encryption_length_) {
    return InvalidArgumentError(
        "PrivateCamenischShoup::Decrypt: ciphertext does not contain the "
        "expected number of components.");
  }

  // Theorem 1 algorithm from Damgaard-Jurik-Nielsen paper, but leverages
  // the fact that lambda = 1. Cancels out the random portion and compute
  // the L function. Remove the randomizer portion of the ciphertext, and
  // compute L = (1+n)^m - 1 mod n^(s+1).

  std::vector<BigNum> ms;
  ms.reserve(vector_encryption_length_);

  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    ASSIGN_OR_RETURN(BigNum s,
                     ct.u.ModExp(xs_[i], modulus_).ModInverse(modulus_));
    BigNum denoised = ct.es[i].ModMul(s, modulus_);

    // m_j holds m mod n^j at the end of the j'th iteration. At the start of
    // the loop, it holds m mod 1 = 0, and at the end it will hold m mod n^s,
    // namely the output.
    BigNum m_j = ctx_->CreateBigNum(0);  // m_j holds i_j, and i_0 = 0.
    for (uint64_t j = 1; j <= s_; j++) {
      BigNum intermediate = denoised.Mod(powers_of_n_[j + 1]) - ctx_->One();
      if (!intermediate.Mod(n_).IsZero()) {
        return InvalidArgumentError("Corrupt/invalid ciphertext");
      }
      // l_u = ((denoised mod n^(j+1)) - 1)/ n , or L(denoised mod n^(j+1))
      BigNum l_u = intermediate.Div(n_);

      BigNum t1 = l_u;  // t1 starts as l_u
      BigNum t2 = m_j;  // t2 starts as i_(j-1)
      for (uint64_t k = 2; k <= j; k++) {
        m_j = m_j - ctx_->One();
        t2 = t2.ModMul(m_j, powers_of_n_[j]);
        t1 = t1 - (t2.ModMul(decryption_precomp_.at({k, j}), powers_of_n_[j]));
      }
      // t_1 now holds L(denoised mod n^(j+1)) -
      // ((Sum_{k=2}^s Choose (i_(j-1), k) * n^(k-1)) mod n^j), which is
      // exactly i_j, which is m mod n^j
      m_j = std::move(t1);
    }
    ms.push_back(m_j.Mod(powers_of_n_[s_]));
  }

  return std::move(ms);
}

StatusOr<CamenischShoupCiphertext> PrivateCamenischShoup::ParseCiphertextProto(
    const proto::CamenischShoupCiphertext& ciphertext_proto) {
  return CommonParseCiphertextProto(ctx_, modulus_, vector_encryption_length_,
                                    ciphertext_proto);
}

}  // namespace private_join_and_compute
