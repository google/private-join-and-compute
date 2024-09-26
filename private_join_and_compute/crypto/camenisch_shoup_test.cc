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

// Unit Tests for CamenischShoup.

#include "private_join_and_compute/crypto/camenisch_shoup.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace {
using ::testing::Eq;
using ::testing::HasSubstr;
using testing::IsOkAndHolds;
using testing::StatusIs;
using ::testing::TestWithParam;

inline uint64_t PowInt(uint64_t base, int exponent) {
  return static_cast<uint64_t>(std::pow(base, exponent));
}

const uint64_t P = 5;
const uint64_t Q = 7;
const uint64_t N = P * Q;
const uint64_t S = 1;
const uint64_t N_TO_S_PLUS_1 = PowInt(N, S + 1);
const uint64_t G = 607;
const uint64_t X = 2;
const uint64_t Y = PowInt(G, X) % N_TO_S_PLUS_1;

TEST(GenerateCamenischShoupKeyTest, GenerateKey) {
  Context ctx;
  int64_t n_length_bits = 32;
  for (uint64_t s : {1, 2, 5}) {
    for (uint64_t vector_commitment_length : {1, 2, 5}) {
      CamenischShoupKey key = GenerateCamenischShoupKey(
          &ctx, n_length_bits, s, vector_commitment_length);
      // Check primes are the right length.
      EXPECT_EQ(key.p.BitLength(), n_length_bits / 2);
      EXPECT_EQ(key.q.BitLength(), n_length_bits / 2);
      // Check n = p*q
      EXPECT_EQ(key.n, key.p * key.q);
      EXPECT_EQ(s, key.s);
      BigNum n_to_s_plus_one = key.n.Exp(ctx.CreateBigNum(s + 1));
      BigNum phi_n = (key.p - ctx.One()) * (key.q - ctx.One());
      // Check that g has the right order.
      EXPECT_EQ(ctx.One(), key.g.ModExp(phi_n, n_to_s_plus_one));
      // Check that xs and ys have the right length and the right form.
      EXPECT_EQ(key.ys.size(), vector_commitment_length);
      EXPECT_EQ(key.xs.size(), vector_commitment_length);
      for (uint64_t i = 0; i < vector_commitment_length; i++) {
        EXPECT_EQ(key.ys[i], key.g.ModExp(key.xs[i], n_to_s_plus_one));
        EXPECT_TRUE(key.xs[i].Gcd(key.n).IsOne());
        EXPECT_LT(key.xs[i], key.n);
      }
    }
  }
}

TEST(GenerateCamenischShoupKeyTest, GenerateKeyPair) {
  Context ctx;
  BigNum n = ctx.CreateBigNum(N);
  BigNum phi_n = ctx.CreateBigNum((P - 1) * (Q - 1));
  uint64_t s = 2;
  uint64_t vector_commitment_length = 2;
  std::unique_ptr<CamenischShoupPublicKey> public_key;
  std::unique_ptr<CamenischShoupPrivateKey> private_key;

  std::tie(public_key, private_key) =
      GenerateCamenischShoupKeyPair(&ctx, n, s, vector_commitment_length);
  EXPECT_EQ(s, public_key->s);
  BigNum n_to_s_plus_one = public_key->n.Exp(ctx.CreateBigNum(s + 1));

  // Check that g has the right order.
  EXPECT_EQ(ctx.One(), public_key->g.ModExp(phi_n, n_to_s_plus_one));
  // Check that xs and ys have the right length and the right form.
  EXPECT_EQ(public_key->ys.size(), vector_commitment_length);
  EXPECT_EQ(private_key->xs.size(), vector_commitment_length);
  for (uint64_t i = 0; i < vector_commitment_length; i++) {
    EXPECT_EQ(public_key->ys[i],
              public_key->g.ModExp(private_key->xs[i], n_to_s_plus_one));
    EXPECT_TRUE(private_key->xs[i].Gcd(public_key->n).IsOne());
    EXPECT_LT(private_key->xs[i], public_key->n);
  }
}

// A test fixture for Serializing CamenischShoup Keys.
class SerializeCamenischShoupKeyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    BigNum n = ctx_.CreateBigNum(N);
    BigNum phi_n = ctx_.CreateBigNum((P - 1) * (Q - 1));
    uint64_t s = 2;
    int64_t vector_commitment_length = 2;

    std::tie(public_key_, private_key_) =
        GenerateCamenischShoupKeyPair(&ctx_, n, s, vector_commitment_length);
  }

  Context ctx_;
  std::unique_ptr<CamenischShoupPublicKey> public_key_;
  std::unique_ptr<CamenischShoupPrivateKey> private_key_;
};

TEST_F(SerializeCamenischShoupKeyTest, SerializeAndDeserializeKeyPair) {
  // Serialize and deserialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupPublicKey public_key_deserialized,
      ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto));

  // Serialize and deserialize private key
  proto::CamenischShoupPrivateKey private_key_proto =
      CamenischShoupPrivateKeyToProto(*private_key_);
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupPrivateKey private_key_deserialized,
      ParseCamenischShoupPrivateKeyProto(&ctx_, private_key_proto));

  // Check that fields all line up correctly.
  EXPECT_EQ(public_key_->n, public_key_deserialized.n);
  EXPECT_EQ(public_key_->s, public_key_deserialized.s);
  EXPECT_EQ(public_key_->vector_encryption_length,
            public_key_deserialized.vector_encryption_length);
  EXPECT_EQ(public_key_->g, public_key_deserialized.g);
  EXPECT_EQ(public_key_->ys, public_key_deserialized.ys);
  EXPECT_EQ(private_key_->xs, private_key_deserialized.xs);
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenNIsMissing) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);

  // Clear n.
  proto::CamenischShoupPublicKey public_key_proto_no_n = public_key_proto;
  public_key_proto_no_n.clear_n();
  EXPECT_THAT(ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_no_n),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" n ")));
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenSIsMissing) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);

  // Clear s.
  proto::CamenischShoupPublicKey public_key_proto_no_s = public_key_proto;
  public_key_proto_no_s.clear_s();
  EXPECT_THAT(ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_no_s),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" s ")));
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenGIsMissing) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);
  // Clear g.
  proto::CamenischShoupPublicKey public_key_proto_no_g = public_key_proto;
  public_key_proto_no_g.clear_g();
  EXPECT_THAT(
      ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_no_g),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid g")));
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenYsIsMissing) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);
  // Clear ys.
  proto::CamenischShoupPublicKey public_key_proto_no_ys = public_key_proto;
  public_key_proto_no_ys.clear_ys();
  EXPECT_THAT(
      ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_no_ys),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("empty ys")));
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenGIsOutOfBounds) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);
  BigNum out_of_bounds = ctx_.CreateBigNum(N).Exp(ctx_.CreateBigNum(2 * S));
  // Set g out of bounds.
  proto::CamenischShoupPublicKey public_key_proto_big_g = public_key_proto;
  public_key_proto_big_g.set_g(out_of_bounds.ToBytes());
  EXPECT_THAT(
      ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_big_g),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid g")));
}

TEST_F(SerializeCamenischShoupKeyTest,
       DeserializingPublicKeyFailsWhenYsIsOutOfBounds) {
  // Serialize public key
  proto::CamenischShoupPublicKey public_key_proto =
      CamenischShoupPublicKeyToProto(*public_key_);
  // Set ys[0] out of bounds.
  BigNum out_of_bounds = ctx_.CreateBigNum(N).Exp(ctx_.CreateBigNum(2 * S));
  proto::CamenischShoupPublicKey public_key_proto_big_ys = public_key_proto;
  std::vector<BigNum> big_ys = public_key_->ys;
  big_ys[0] = out_of_bounds;
  *public_key_proto_big_ys.mutable_ys() = BigNumVectorToProto(big_ys);
  EXPECT_THAT(ParseCamenischShoupPublicKeyProto(&ctx_, public_key_proto_big_ys),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("ys")));
}

// A test fixture for CamenischShoup.
class CamenischShoupTest : public ::testing::Test {
 protected:
  void SetUp() override {
    public_cam_shoup_ = std::make_unique<PublicCamenischShoup>(
        &ctx_, ctx_.CreateBigNum(N), S, ctx_.CreateBigNum(G),
        std::vector<BigNum>({ctx_.CreateBigNum(Y)}));
    private_cam_shoup_ = std::make_unique<PrivateCamenischShoup>(
        &ctx_, ctx_.CreateBigNum(N), S, ctx_.CreateBigNum(G),
        std::vector<BigNum>({ctx_.CreateBigNum(Y)}),
        std::vector<BigNum>({ctx_.CreateBigNum(X)}));
  }

  Context ctx_;
  std::unique_ptr<PublicCamenischShoup> public_cam_shoup_;
  std::unique_ptr<PrivateCamenischShoup> private_cam_shoup_;
};

TEST_F(CamenischShoupTest, TestEncryptWithRand) {
  BigNum r = ctx_.Three();
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupCiphertext ct,
      private_cam_shoup_->EncryptWithRand({ctx_.CreateBigNum(2)}, r));
  EXPECT_EQ(ctx_.CreateBigNum(293),  // (607)^(3) mod 35^2
            ct.u);
  EXPECT_EQ(ctx_.CreateBigNum(904),  // (949)^(3) * (1 + 70) mod 35^2
            ct.es[0]);
}

TEST_F(CamenischShoupTest, TestEncryptAndGetRand) {
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupCiphertextWithRand ct_with_rand,
      private_cam_shoup_->EncryptAndGetRand({ctx_.CreateBigNum(2)}));
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->EncryptWithRand(
                           {ctx_.CreateBigNum(2)}, ct_with_rand.r));
  EXPECT_EQ(ct.u, ct_with_rand.ct.u);
  EXPECT_EQ(ct.es[0], ct_with_rand.ct.es[0]);
}

TEST_F(CamenischShoupTest, TestEncryptFailsForNegativeMessage) {
  auto maybe_result = private_cam_shoup_->Encrypt({-ctx_.One()});
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("Cannot encrypt negative number"));
}

TEST_F(CamenischShoupTest, TestEncryptWithRandFailsForInvalidRandomness) {
  BigNum m = ctx_.CreateBigNum(2);

  // Negative randomness
  BigNum r = -ctx_.Three();
  auto maybe_result_1 = private_cam_shoup_->EncryptWithRand({m}, r);
  EXPECT_TRUE(IsInvalidArgument(maybe_result_1.status()));
  EXPECT_THAT(maybe_result_1.status().message(), HasSubstr(">=0"));

  // r not relatively prime to n.
  r = ctx_.CreateBigNum(P);
  auto maybe_result_2 = private_cam_shoup_->EncryptWithRand({m}, r);
  EXPECT_TRUE(IsInvalidArgument(maybe_result_2.status()));
  EXPECT_THAT(maybe_result_2.status().message(),
              HasSubstr("not share prime factors"));
}

TEST_F(CamenischShoupTest, TestEncryptWithDifferentRandoms) {
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct1,
                       private_cam_shoup_->Encrypt({ctx_.CreateBigNum(2)}));
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct2,
                       private_cam_shoup_->Encrypt({ctx_.CreateBigNum(2)}));
  EXPECT_NE(ct1.u, ct2.u);
  EXPECT_NE(ct1.es[0], ct2.es[0]);
}

TEST_F(CamenischShoupTest, TestDecryptFailsWithCorruptCiphertext) {
  CamenischShoupCiphertext ct =
      CamenischShoupCiphertext{ctx_.Two(), {ctx_.Two()}};
  auto maybe_result = private_cam_shoup_->Decrypt(ct);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("Corrupt/invalid ciphertext"));
}

TEST_F(CamenischShoupTest, TestEncryptAndDecryptOneToTen) {
  private_cam_shoup_ = std::make_unique<PrivateCamenischShoup>(
      &ctx_, ctx_.CreateBigNum(N), S, ctx_.CreateBigNum(G),
      std::vector<BigNum>({ctx_.CreateBigNum(Y)}),
      std::vector<BigNum>({ctx_.CreateBigNum(X)}));
  for (int i = 0; i < 10; i++) {
    BigNum bn_i = ctx_.CreateBigNum(i);
    ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                         private_cam_shoup_->Encrypt({bn_i}));
    ASSERT_OK_AND_ASSIGN(auto decrypted_value, private_cam_shoup_->Decrypt(ct));
    EXPECT_EQ(bn_i, decrypted_value[0]);
  }
}

TEST_F(CamenischShoupTest, TestEncryptAndDecryptLargeMessage) {
  BigNum m = ctx_.CreateBigNum(N + 2);
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->Encrypt({m}));
  ASSERT_OK_AND_ASSIGN(auto decrypted_value, private_cam_shoup_->Decrypt(ct));
  EXPECT_EQ(m.Mod(ctx_.CreateBigNum(N)), decrypted_value[0]);
}

TEST_F(CamenischShoupTest, TestPublicEncryptOneAndDecrypt) {
  public_cam_shoup_ = std::make_unique<PublicCamenischShoup>(
      &ctx_, ctx_.CreateBigNum(N), S, ctx_.CreateBigNum(G),
      std::vector<BigNum>({ctx_.CreateBigNum(Y)}));
  private_cam_shoup_ = std::make_unique<PrivateCamenischShoup>(
      &ctx_, ctx_.CreateBigNum(N), S, ctx_.CreateBigNum(G),
      std::vector<BigNum>({ctx_.CreateBigNum(Y)}),
      std::vector<BigNum>({ctx_.CreateBigNum(X)}));
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       public_cam_shoup_->Encrypt({ctx_.One()}));
  ASSERT_OK_AND_ASSIGN(auto decrypted_value, private_cam_shoup_->Decrypt(ct));
  EXPECT_EQ(ctx_.CreateBigNum(1), decrypted_value[0]);
}

TEST_F(CamenischShoupTest, TestPublicEncryptWithRand) {
  BigNum r = ctx_.Three();
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupCiphertext ct,
      public_cam_shoup_->EncryptWithRand({ctx_.CreateBigNum(2)}, r));
  EXPECT_EQ(ctx_.CreateBigNum(293),  // (607)^(3) mod 35^2
            ct.u);
  EXPECT_EQ(ctx_.CreateBigNum(904),  // (949)^(3) * (1 + 70) mod 35^2
            ct.es[0]);
}

// A test fixture for CamenischShoup with a large random modulus. The tests are
// parameterized by (s, vector_encryption_length), so that the modulus is
// n^(s+1)), and there are vector_encryption_length secret keys.
class CamenischShoupLargeModulusTest
    : public TestWithParam<std::pair<uint64_t, uint64_t>> {
 protected:
  void SetUp() override {
    std::tie(s_, vector_encryption_length_) = GetParam();
    key_ = std::make_unique<CamenischShoupKey>(GenerateCamenischShoupKey(
        &ctx_, /*n_length_bits=*/32, s_, vector_encryption_length_));
    public_cam_shoup_ = std::make_unique<PublicCamenischShoup>(
        &ctx_, key_->n, key_->s, key_->g, key_->ys);
    private_cam_shoup_ = std::make_unique<PrivateCamenischShoup>(
        &ctx_, key_->n, key_->s, key_->g, key_->ys, key_->xs);
  }

  Context ctx_;
  uint64_t s_;
  uint64_t vector_encryption_length_;
  std::unique_ptr<CamenischShoupKey> key_;
  std::unique_ptr<PublicCamenischShoup> public_cam_shoup_;
  std::unique_ptr<PrivateCamenischShoup> private_cam_shoup_;
};

TEST_P(CamenischShoupLargeModulusTest,
       TestEncryptAndDecryptOneItemWithLargeModulus) {
  ASSERT_OK_AND_ASSIGN(
      auto ct, private_cam_shoup_->Encrypt({ctx_.CreateBigNum(4234234)}));
  ASSERT_OK_AND_ASSIGN(std::vector<BigNum> decrypted,
                       private_cam_shoup_->Decrypt(ct));

  // The first decrypted value should be as expected.
  EXPECT_EQ(ctx_.CreateBigNum(4234234), decrypted[0]);
  EXPECT_EQ(vector_encryption_length_, decrypted.size());

  // The rest should be padded with 0s.
  for (uint64_t i = 1; i < vector_encryption_length_; i++) {
    EXPECT_EQ(decrypted[i], ctx_.Zero());
  }
}

TEST_P(CamenischShoupLargeModulusTest, TestEncryptAndDecryptRandomNumber) {
  std::vector<BigNum> random_messages;
  random_messages.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
  }
  ASSERT_OK_AND_ASSIGN(auto ct, private_cam_shoup_->Encrypt(random_messages));
  EXPECT_THAT(private_cam_shoup_->Decrypt(ct),
              IsOkAndHolds(Eq(random_messages)));
}

TEST_P(CamenischShoupLargeModulusTest, TestAdd) {
  std::vector<BigNum> random_messages_1;
  std::vector<BigNum> random_messages_2;
  std::vector<BigNum> sums;
  random_messages_1.reserve(vector_encryption_length_);
  random_messages_2.reserve(vector_encryption_length_);
  sums.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages_1.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
    random_messages_2.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
    sums.push_back(random_messages_1[i].ModAdd(
        random_messages_2[i], public_cam_shoup_->message_upper_bound()));
  }

  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct1,
                       public_cam_shoup_->Encrypt(random_messages_1));
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct2,
                       public_cam_shoup_->Encrypt(random_messages_2));

  CamenischShoupCiphertext sum_ct = public_cam_shoup_->Add(ct1, ct2);

  EXPECT_THAT(private_cam_shoup_->Decrypt(sum_ct), IsOkAndHolds(Eq(sums)));
}

TEST_P(CamenischShoupLargeModulusTest, TestMultiply) {
  std::vector<BigNum> random_messages;
  BigNum scalar = ctx_.CreateBigNum(3);
  std::vector<BigNum> products;
  random_messages.reserve(vector_encryption_length_);
  products.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
    products.push_back(random_messages[i].ModMul(
        scalar, public_cam_shoup_->message_upper_bound()));
  }

  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       public_cam_shoup_->Encrypt(random_messages));

  CamenischShoupCiphertext prod_ct = public_cam_shoup_->Multiply(ct, scalar);

  EXPECT_THAT(private_cam_shoup_->Decrypt(prod_ct), IsOkAndHolds(Eq(products)));
}

TEST_P(CamenischShoupLargeModulusTest, SerializeAndDeserializeCiphertext) {
  std::vector<BigNum> random_messages;
  random_messages.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
  }
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->Encrypt(random_messages));

  proto::CamenischShoupCiphertext serialized_ciphertext =
      CamenischShoupCiphertextToProto(ct);
  ASSERT_OK_AND_ASSIGN(
      CamenischShoupCiphertext deserialized_ciphertext,
      private_cam_shoup_->ParseCiphertextProto(serialized_ciphertext));

  EXPECT_EQ(ct.u, deserialized_ciphertext.u);
  EXPECT_EQ(ct.es, deserialized_ciphertext.es);
}

TEST_P(CamenischShoupLargeModulusTest,
       DeserializingCiphertextFailsWhenUOutOfBounds) {
  std::vector<BigNum> random_messages;
  random_messages.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
  }
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->Encrypt(random_messages));

  proto::CamenischShoupCiphertext serialized_ciphertext =
      CamenischShoupCiphertextToProto(ct);

  BigNum out_of_bounds = public_cam_shoup_->modulus() + ctx_.One();
  // Out of Bounds u.
  proto::CamenischShoupCiphertext serialized_ciphertext_u_out_of_bounds =
      serialized_ciphertext;
  serialized_ciphertext_u_out_of_bounds.set_u(out_of_bounds.ToBytes());
  EXPECT_THAT(private_cam_shoup_->ParseCiphertextProto(
                  serialized_ciphertext_u_out_of_bounds),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" u")));
}

TEST_P(CamenischShoupLargeModulusTest,
       DeserializingCiphertextFailsWhenTooManyEs) {
  std::vector<BigNum> random_messages;
  random_messages.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
  }
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->Encrypt(random_messages));

  proto::CamenischShoupCiphertext serialized_ciphertext =
      CamenischShoupCiphertextToProto(ct);

  // Too many es.
  proto::CamenischShoupCiphertext serialized_ciphertext_too_many_es =
      serialized_ciphertext;
  std::vector<BigNum> too_many_es = ct.es;
  too_many_es.push_back(ctx_.Zero());
  *serialized_ciphertext_too_many_es.mutable_es() =
      BigNumVectorToProto(too_many_es);
  EXPECT_THAT(private_cam_shoup_->ParseCiphertextProto(
                  serialized_ciphertext_too_many_es),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" es")));
}

TEST_P(CamenischShoupLargeModulusTest,
       DeserializingCiphertextFailsWhenEsOutOfBounds) {
  std::vector<BigNum> random_messages;
  random_messages.reserve(vector_encryption_length_);
  for (uint64_t i = 0; i < vector_encryption_length_; i++) {
    random_messages.push_back(
        ctx_.GenerateRandLessThan(public_cam_shoup_->message_upper_bound()));
  }
  ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext ct,
                       private_cam_shoup_->Encrypt(random_messages));

  proto::CamenischShoupCiphertext serialized_ciphertext =
      CamenischShoupCiphertextToProto(ct);

  BigNum out_of_bounds = public_cam_shoup_->modulus() + ctx_.One();

  // es out of bounds.
  proto::CamenischShoupCiphertext serialized_ciphertext_es_out_of_bounds =
      serialized_ciphertext;
  std::vector<BigNum> es_out_of_bounds = ct.es;
  es_out_of_bounds[0] = out_of_bounds;
  *serialized_ciphertext_es_out_of_bounds.mutable_es() =
      BigNumVectorToProto(es_out_of_bounds);
  EXPECT_THAT(private_cam_shoup_->ParseCiphertextProto(
                  serialized_ciphertext_es_out_of_bounds),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" es")));
}

TEST_P(CamenischShoupLargeModulusTest,
       DeserializingEmptyCiphertextGivesCiphertextWithEmptyEs) {
  proto::CamenischShoupCiphertext serialized_ciphertext;  // Default instance.

  ASSERT_OK_AND_ASSIGN(
      CamenischShoupCiphertext deserialized,
      private_cam_shoup_->ParseCiphertextProto(serialized_ciphertext));

  EXPECT_TRUE(deserialized.es.empty());
}

INSTANTIATE_TEST_SUITE_P(CamenischShoupLargeModulusTestWithDifferentS,
                         CamenischShoupLargeModulusTest,
                         ::testing::Values(std::make_pair(1, 1),
                                           std::make_pair(5, 1),
                                           std::make_pair(1, 5),
                                           std::make_pair(5, 5)));

}  // namespace
}  // namespace private_join_and_compute
