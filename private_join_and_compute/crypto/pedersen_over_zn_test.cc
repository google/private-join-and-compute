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

#include "private_join_and_compute/crypto/pedersen_over_zn.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace {

using ::testing::HasSubstr;
using testing::IsOkAndHolds;
using testing::StatusIs;

const uint64_t P = 5;
const uint64_t Q = 7;
const uint64_t N = P * Q;
const uint64_t H = 31;  // corresponds to -(2^2) mod N.
const uint64_t R = 5;
const uint64_t G = 26;  // G = H^R mod N
const uint64_t G2 = 6;
const uint64_t P_XL = 35879;
const uint64_t Q_XL = 63587;
const uint64_t N_XL = P_XL * Q_XL;

const uint64_t NUM_REPETITIONS = 20;
const uint64_t CHALLENGE_LENGTH = 4;
const uint64_t ZK_QUALITY = 4;

// A test fixture for PedersenOverZn.
class PedersenOverZnTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::vector<BigNum> bases = {ctx_.CreateBigNum(G)};
    pedersen_ = PedersenOverZn::Create(&ctx_, bases, ctx_.CreateBigNum(H),
                                       ctx_.CreateBigNum(N))
                    .value();
  }

  Context ctx_;
  std::unique_ptr<PedersenOverZn> pedersen_;
};

TEST_F(PedersenOverZnTest, SplitVector) {
  Context ctx;
  int subvector_size = 7;
  int num_inputs = 1000;

  // Generate a random vector of BigNums.
  BigNum bound = ctx.CreateBigNum(100000);
  std::vector<BigNum> input;
  for (int i = 0; i < num_inputs; i++) {
    input.push_back(ctx.GenerateRandLessThan(bound));
  }

  // Split the vector into subvectors.
  auto output = SplitVector(input, subvector_size);

  // Expect that the splitting happened properly.
  // Correct number of subvectors.
  int expected_num_subvectors =
      (num_inputs + subvector_size - 1) / subvector_size;
  EXPECT_EQ(output.size(), expected_num_subvectors);

  // Last subvector has the expected size.
  if (num_inputs % subvector_size != 0) {
    EXPECT_EQ(output[expected_num_subvectors - 1].size(),
              num_inputs % subvector_size);
  }

  // Each entry of each subvector is correct.
  for (int i = 0; i < num_inputs; i++) {
    EXPECT_EQ(input[i], output[i / subvector_size][i % subvector_size]);
  }
}

TEST_F(PedersenOverZnTest, TestFromProto) {
  proto::PedersenParameters parameters_proto;
  parameters_proto.set_n(pedersen_->n().ToBytes());
  parameters_proto.set_h(pedersen_->h().ToBytes());
  *parameters_proto.mutable_gs() = BigNumVectorToProto(pedersen_->gs());

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<PedersenOverZn> from_proto,
                       PedersenOverZn::FromProto(&ctx_, parameters_proto));
  EXPECT_EQ(from_proto->n(), pedersen_->n());
  EXPECT_EQ(from_proto->h(), pedersen_->h());
  EXPECT_EQ(from_proto->gs(), pedersen_->gs());
}

TEST_F(PedersenOverZnTest,
       TestGeneratePedersenOverZnParametersWithLargeModulus) {
  BigNum n = ctx_.CreateBigNum(N_XL);
  int64_t num_gs = 5;
  PedersenOverZn::Parameters params =
      PedersenOverZn::GenerateParameters(&ctx_, n, num_gs);
  // n copied correctly
  EXPECT_EQ(params.n, n);
  // g = h^r mod n
  for (int i = 0; i < num_gs; i++) {
    EXPECT_EQ(params.gs[i], params.h.ModExp(params.rs[i], params.n));
  }

  // test that g and h are actually generators, that is:
  // (i) they are each in Z*n
  for (int i = 0; i < num_gs; i++) {
    EXPECT_EQ(ctx_.One(), params.gs[i].Gcd(n));
  }
  EXPECT_EQ(ctx_.One(), params.h.Gcd(n));

  // (ii) they are not generators of the smaller subgroups of order 2, (p-1)/2
  // and (q-1)/2 respectively
  for (int i = 0; i < num_gs; i++) {
    EXPECT_NE(ctx_.One(), params.gs[i].ModExp(ctx_.Two(), n));
  }
  EXPECT_NE(ctx_.One(), params.h.ModExp(ctx_.Two(), n));

  BigNum bn_i = ctx_.CreateBigNum((P_XL - 1) / 2);
  for (int i = 0; i < num_gs; i++) {
    EXPECT_NE(ctx_.One(), params.gs[i].ModExp(bn_i, n));
  }
  EXPECT_NE(ctx_.One(), params.h.ModExp(bn_i, n));

  bn_i = ctx_.CreateBigNum((Q_XL - 1) / 2);
  for (int i = 0; i < num_gs; i++) {
    EXPECT_NE(ctx_.One(), params.gs[i].ModExp(bn_i, n));
  }
  EXPECT_NE(ctx_.One(), params.h.ModExp(bn_i, n));

  // (iii) g^i and h^i = 1 for i = the order of the subgroup of quadratic
  // residues
  bn_i = ctx_.CreateBigNum(((P_XL - 1) * (Q_XL - 1)) / 4);
  for (int i = 0; i < num_gs; i++) {
    EXPECT_EQ(ctx_.One(), params.gs[i].ModExp(bn_i, n));
  }
  EXPECT_EQ(ctx_.One(), params.h.ModExp(bn_i, n));
}

TEST_F(PedersenOverZnTest, TestCommitFailsWithInvalidMessage) {
  // Negative value.
  BigNum neg_one = ctx_.Zero() - ctx_.One();
  auto maybe_result = pedersen_->Commit({neg_one});
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("cannot commit to negative value."));

  // Should work fine.
  EXPECT_FALSE(
      IsInvalidArgument(pedersen_->Commit({ctx_.CreateBigNum(8)}).status()));
}

TEST_F(PedersenOverZnTest, TestVerifyComplainsOnInvalidArguments) {
  PedersenOverZn::Commitment com = ctx_.Zero();

  // Negative message
  PedersenOverZn::Opening open = ctx_.Zero();
  auto maybe_result = pedersen_->Verify(com, {-ctx_.One()}, open);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("message in the opening is negative"));

  // Negative randomness
  open = -ctx_.One();
  maybe_result = pedersen_->Verify(com, {ctx_.Zero()}, open);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("randomness in the opening is negative"));
}

TEST_F(PedersenOverZnTest, TestCommitAndVerifyZero) {
  ASSERT_OK_AND_ASSIGN(auto commit_and_open, pedersen_->Commit({ctx_.Zero()}));
  PedersenOverZn::Commitment com = std::move(commit_and_open.commitment);
  PedersenOverZn::Opening open = std::move(commit_and_open.opening);
  EXPECT_THAT(pedersen_->Verify(com, {ctx_.Zero()}, open), IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, TestCommitAndVerifyTwo) {
  ASSERT_OK_AND_ASSIGN(auto commit_and_open, pedersen_->Commit({ctx_.Two()}));
  PedersenOverZn::Commitment com = std::move(commit_and_open.commitment);
  PedersenOverZn::Opening open = std::move(commit_and_open.opening);
  EXPECT_THAT(pedersen_->Verify(com, {ctx_.Two()}, open), IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, VerifyFailsOnIncorrectOpening) {
  BigNum message = ctx_.Two();
  ASSERT_OK_AND_ASSIGN(auto commit_and_open, pedersen_->Commit({message}));
  PedersenOverZn::Commitment com = std::move(commit_and_open.commitment);
  PedersenOverZn::Opening open = std::move(commit_and_open.opening);

  BigNum wrong_message = ctx_.Zero();
  EXPECT_THAT(pedersen_->Verify(com, {wrong_message}, open),
              IsOkAndHolds(false));

  PedersenOverZn::Opening wrong_random = open + ctx_.One();
  EXPECT_THAT(pedersen_->Verify(com, {message}, wrong_random),
              IsOkAndHolds(false));
}

TEST_F(PedersenOverZnTest, TestGenerateLargeParamsCommitAndVerify) {
  PedersenOverZn::Parameters params =
      PedersenOverZn::GenerateParameters(&ctx_, ctx_.CreateBigNum(N_XL));
  ASSERT_OK_AND_ASSIGN(
      pedersen_, PedersenOverZn::Create(&ctx_, params.gs, params.h, params.n));

  BigNum n_by_four = params.n.DivAndTruncate(ctx_.CreateBigNum(4));
  BigNum m = ctx_.GenerateRandLessThan(n_by_four);

  ASSERT_OK_AND_ASSIGN(auto commit_and_open, pedersen_->Commit({m}));
  PedersenOverZn::Commitment com = std::move(commit_and_open.commitment);
  PedersenOverZn::Opening open = std::move(commit_and_open.opening);
  EXPECT_THAT(pedersen_->Verify(com, {m}, open), IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, TestCommitWithRandAndVerifyZero) {
  ASSERT_OK_AND_ASSIGN(PedersenOverZn::Commitment com,
                       pedersen_->CommitWithRand({ctx_.Zero()}, ctx_.Three()));
  EXPECT_THAT(pedersen_->Verify(com, {ctx_.Zero()}, ctx_.Three()),
              IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, TestCommitWithRandAndVerifyTwo) {
  ASSERT_OK_AND_ASSIGN(PedersenOverZn::Commitment com,
                       pedersen_->CommitWithRand({ctx_.Two()}, ctx_.Three()));
  EXPECT_THAT(pedersen_->Verify(com, {ctx_.Two()}, ctx_.Three()),
              IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest,
       TestCommitWithRandComplainsOnNegativeMessageAndRandomness) {
  // Negative message
  auto maybe_result = pedersen_->CommitWithRand({-ctx_.Two()}, ctx_.One());
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("cannot commit to negative value."));

  // Negative randomness
  maybe_result = pedersen_->CommitWithRand({ctx_.Two()}, -ctx_.One());
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("randomness must be nonnegative."));
}

TEST_F(PedersenOverZnTest, TestAdd) {
  ASSERT_OK_AND_ASSIGN(auto commit_and_open_1, pedersen_->Commit({ctx_.One()}));
  ASSERT_OK_AND_ASSIGN(auto commit_and_open_2, pedersen_->Commit({ctx_.Two()}));
  auto commit_3 = pedersen_->Add(commit_and_open_1.commitment,
                                 commit_and_open_2.commitment);

  // Verifies that the opening randomness of commit_3 is the sum of the
  // opening randomness in commit_and_open_1 and commit_and_open_2.
  auto randomness_in_commit_3 =
      commit_and_open_1.opening + commit_and_open_2.opening;
  EXPECT_TRUE(
      pedersen_->Verify(commit_3, {ctx_.Three()}, randomness_in_commit_3).ok());
}

TEST_F(PedersenOverZnTest, TestMultiply) {
  ASSERT_OK_AND_ASSIGN(auto commit_and_open_2, pedersen_->Commit({ctx_.Two()}));
  auto commit_6 =
      pedersen_->Multiply(commit_and_open_2.commitment, ctx_.Three());

  // Verifies that the opening randomness of commit_6 is 3 times the opening
  // randomness in commit_and_open_2.
  auto randomness_in_commit_6 = commit_and_open_2.opening * ctx_.Three();
  EXPECT_TRUE(
      pedersen_
          ->Verify(commit_6, {ctx_.CreateBigNum(6)}, randomness_in_commit_6)
          .ok());
}

TEST_F(PedersenOverZnTest, TestCommitFailsWithTooManyMessages) {
  // Commit with the default parameters can handle at most 1 message, 2
  // provided.
  auto maybe_result = pedersen_->Commit({ctx_.One(), ctx_.Zero()});
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("too many messages provided"));
}

TEST_F(PedersenOverZnTest, TestVerifyFailsWithTooManyMessages) {
  ASSERT_OK_AND_ASSIGN(auto commit_and_rand, pedersen_->Commit({ctx_.One()}));
  // Verify can handle at most 1 message, 2 provided.
  auto maybe_result =
      pedersen_->Verify(commit_and_rand.commitment, {ctx_.One(), ctx_.Zero()},
                        commit_and_rand.opening);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("too many messages provided"));
}

TEST_F(PedersenOverZnTest, TestCommitAndVerifyWithMultipleGs) {
  // Two gs, two messages.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  std::vector<BigNum> messages = {ctx_.Two(), ctx_.Three()};
  ASSERT_OK_AND_ASSIGN(auto multi_pedersen,
                       PedersenOverZn::Create(&ctx_, gs, ctx_.CreateBigNum(H),
                                              ctx_.CreateBigNum(N)));

  ASSERT_OK_AND_ASSIGN(auto commit_and_rand, multi_pedersen->Commit(messages));
  EXPECT_THAT(multi_pedersen->Verify(commit_and_rand.commitment, messages,
                                     commit_and_rand.opening),
              IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, TestCommitAndVerifyWithFewerMessagesThanGs) {
  // Two gs, one message.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  std::vector<BigNum> messages = {ctx_.Two()};
  ASSERT_OK_AND_ASSIGN(auto multi_pedersen,
                       PedersenOverZn::Create(&ctx_, gs, ctx_.CreateBigNum(H),
                                              ctx_.CreateBigNum(N)));

  ASSERT_OK_AND_ASSIGN(auto commit_and_rand, multi_pedersen->Commit(messages));
  EXPECT_THAT(multi_pedersen->Verify(commit_and_rand.commitment, messages,
                                     commit_and_rand.opening),
              IsOkAndHolds(true));
}

TEST_F(PedersenOverZnTest, TestCommitAndVerifyWifDifferentPrecomputation) {
  // Two gs, two messages.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  std::vector<BigNum> messages = {ctx_.Two(), ctx_.Three()};
  ASSERT_OK_AND_ASSIGN(
      auto multi_pedersen_1,
      PedersenOverZn::Create(&ctx_, gs, ctx_.CreateBigNum(H),
                             ctx_.CreateBigNum(N),
                             /*num_simultaneous_exponentiations= */ 1));

  ASSERT_OK_AND_ASSIGN(
      auto multi_pedersen_2,
      PedersenOverZn::Create(&ctx_, gs, ctx_.CreateBigNum(H),
                             ctx_.CreateBigNum(N),
                             /*num_simultaneous_exponentiations= */ 2));

  // Test consistency between commitments with the two different pedersen
  // objects. This will imply consistency of verification as well.
  ASSERT_OK_AND_ASSIGN(auto commit_and_rand_1,
                       multi_pedersen_1->Commit(messages));
  ASSERT_OK_AND_ASSIGN(auto commit_2, multi_pedersen_2->CommitWithRand(
                                          messages, commit_and_rand_1.opening));
  EXPECT_EQ(commit_and_rand_1.commitment, commit_2);
}

TEST_F(PedersenOverZnTest, SerializeAndDeserializeParameters) {
  // Two gs, two messages.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  PedersenOverZn::Parameters parameters{
      std::move(gs), ctx_.CreateBigNum(H), ctx_.CreateBigNum(N), {}};

  proto::PedersenParameters parameters_proto =
      PedersenOverZn::ParametersToProto(parameters);
  ASSERT_OK_AND_ASSIGN(
      PedersenOverZn::Parameters parameters_deserialized,
      PedersenOverZn::ParseParametersProto(&ctx_, parameters_proto));

  EXPECT_EQ(parameters.gs, parameters_deserialized.gs);
  EXPECT_EQ(parameters.h, parameters_deserialized.h);
  EXPECT_EQ(parameters.n, parameters_deserialized.n);
}

TEST_F(PedersenOverZnTest, DeserializingParametersFailsWhenGsOutOfBounds) {
  // Two gs, two messages.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  PedersenOverZn::Parameters parameters{
      gs, ctx_.CreateBigNum(H), ctx_.CreateBigNum(N), {}};

  proto::PedersenParameters parameters_proto =
      PedersenOverZn::ParametersToProto(parameters);

  BigNum out_of_bounds = ctx_.CreateBigNum(N) + ctx_.One();

  // g out of bounds
  proto::PedersenParameters parameters_proto_gs_out_of_bounds =
      parameters_proto;
  std::vector<BigNum> gs_out_of_bounds = gs;
  gs_out_of_bounds[0] = out_of_bounds;
  *parameters_proto_gs_out_of_bounds.mutable_gs() =
      BigNumVectorToProto(gs_out_of_bounds);
  EXPECT_THAT(PedersenOverZn::ParseParametersProto(
                  &ctx_, parameters_proto_gs_out_of_bounds),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" g ")));
}

TEST_F(PedersenOverZnTest, DeserializingParametersFailsWhenHOutOfBounds) {
  // Two gs, two messages.
  std::vector<BigNum> gs = {ctx_.CreateBigNum(G), ctx_.CreateBigNum(G2)};
  PedersenOverZn::Parameters parameters{
      gs, ctx_.CreateBigNum(H), ctx_.CreateBigNum(N), {}};

  proto::PedersenParameters parameters_proto =
      PedersenOverZn::ParametersToProto(parameters);

  BigNum out_of_bounds = ctx_.CreateBigNum(N) + ctx_.One();

  // h out of bounds
  proto::PedersenParameters parameters_proto_h_out_of_bounds = parameters_proto;
  parameters_proto_h_out_of_bounds.set_h(out_of_bounds.ToBytes());
  EXPECT_THAT(PedersenOverZn::ParseParametersProto(
                  &ctx_, parameters_proto_h_out_of_bounds),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr(" h ")));
}

// A test fixture for proofs that PedersenOverZn parameters were correctly
// generated, for the case when the modulus is not known to be the product of
// 2 safe primes. The proof is automatically reset between tests.
class PedersenOverZnGenProofTest : public ::testing::Test {
 protected:
  PedersenOverZnGenProofTest()
      : ctx_(),
        g_(ctx_.CreateBigNum(G)),
        h_(ctx_.CreateBigNum(H)),
        n_(ctx_.CreateBigNum(N)),
        r_(ctx_.CreateBigNum(R)),
        num_repetitions_(NUM_REPETITIONS),
        zk_quality_(ZK_QUALITY),
        proof_() {}

  void SetUp() override {
    proof_ = std::make_unique<PedersenOverZn::ProofOfGen>(
        PedersenOverZn::ProveParametersCorrectlyGenerated(
            &ctx_, g_, h_, n_, r_, num_repetitions_, zk_quality_)
            .value());
  }

  Context ctx_;
  BigNum g_;
  BigNum h_;
  BigNum n_;
  BigNum r_;
  int num_repetitions_;
  int zk_quality_;
  std::unique_ptr<PedersenOverZn::ProofOfGen> proof_;
};

TEST_F(PedersenOverZnGenProofTest, TestHonestProofVerifies) {
  EXPECT_TRUE(
      PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_).ok());
}

TEST_F(PedersenOverZnGenProofTest, TestChallengesAreBinaryAndDifferent) {
  std::vector<uint8_t> challenges = PedersenOverZn::GetGenProofChallenge(
      &ctx_, g_ + ctx_.One(), h_, n_, proof_->dummy_gs,
      proof_->num_repetitions);
  int sum_of_challenges = 0;
  for (auto& challenge : challenges) {
    EXPECT_TRUE(challenge == 0 || challenge == 1);
    sum_of_challenges += challenge;
  }
  // Use the sum to test that the challenges are not all 0 and not all 1.
  EXPECT_TRUE(sum_of_challenges > 0 &&
              sum_of_challenges < proof_->num_repetitions);
}

TEST_F(PedersenOverZnGenProofTest, TestProofGenerationFailsOnInvalidInputs) {
  auto maybe_result = PedersenOverZn::ProveParametersCorrectlyGenerated(
      &ctx_, g_, h_, n_, r_, 0, zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("number of repetitions must be positive."));

  maybe_result = PedersenOverZn::ProveParametersCorrectlyGenerated(
      &ctx_, g_, h_, n_, r_, num_repetitions_, 0);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("zk_quality parameter must be positive."));

  maybe_result = PedersenOverZn::ProveParametersCorrectlyGenerated(
      &ctx_, g_, ctx_.CreateBigNum(20), n_, r_, num_repetitions_, zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("h is not relatively prime to n."));

  maybe_result = PedersenOverZn::ProveParametersCorrectlyGenerated(
      &ctx_, ctx_.CreateBigNum(2), h_, n_, r_, num_repetitions_, zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(), HasSubstr("g != h^r mod n."));

  maybe_result = PedersenOverZn::ProveParametersCorrectlyGenerated(
      &ctx_, g_, h_, n_, ctx_.CreateBigNum(2), num_repetitions_, zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(), HasSubstr("g != h^r mod n."));
}

TEST_F(PedersenOverZnGenProofTest, TestProofVerificationFailsOnInvalidInputs) {
  Status status;
  // Proof contains invalid number of repetitions parameter
  proof_->num_repetitions = 0;
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("number of repetitions must be positive."));
  proof_->num_repetitions = NUM_REPETITIONS;

  // Proof does not contain exactly "number of repetitions" dummy_gs
  proof_->dummy_gs.push_back(std::make_unique<BigNum>(ctx_.One()));
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(
      status.message(),
      ::testing::HasSubstr("proof is not valid: number of dummy_gs is "
                           "different from number of repetitions specified."));
  proof_->dummy_gs.pop_back();

  // Proof does not contain exactly "number of repetitions" responses
  proof_->responses.push_back(std::make_unique<BigNum>(ctx_.One()));
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(
      status.message(),
      ::testing::HasSubstr("proof is not valid: number of responses is "
                           "different from number of repetitions specified."));
  proof_->responses.pop_back();

  // h is not relatively prime to modulus.
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, ctx_.CreateBigNum(20),
                                             n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("h is not relatively prime to n."));
}

TEST_F(PedersenOverZnGenProofTest, TestProofVerificationFailsOnIncorrectProof) {
  Status status;

  // Change a response
  *(proof_->responses[2]) = (*proof_->responses[2]) + ctx_.One();
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(
      status.message(),
      ::testing::HasSubstr("the proof verification formula fails at index 2"));
  *(proof_->responses[2]) = (*proof_->responses[2]) - ctx_.One();

  // Change g to g+1
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_ + ctx_.One(), h_, n_,
                                             *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("the proof verification formula fails at "));

  // Change a dummy_g
  // Note here that changing "dummy_gs" potentially changes the challenge in
  // every repetition, so we cannot guarantee which repetition is the first to
  // fail.
  *(proof_->dummy_gs[3]) = (*proof_->dummy_gs[3]) + ctx_.One();
  status = PedersenOverZn::VerifyParamsProof(&ctx_, g_, h_, n_, *proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("the proof verification formula fails at "));
}

// A test fixture for proofs that PedersenOverZn parameters were correctly
// generated, for the case when the modulus is already believed to be the
// product of 2 safe primes The proof is automatically reset between tests.
class PedersenOverZnGenProofForTrustedModulusTest : public ::testing::Test {
 protected:
  PedersenOverZnGenProofForTrustedModulusTest()
      : ctx_(),
        g_(ctx_.CreateBigNum(G)),
        h_(ctx_.CreateBigNum(H)),
        n_(ctx_.CreateBigNum(N)),
        r_(ctx_.CreateBigNum(R)),
        challenge_length_(CHALLENGE_LENGTH),
        zk_quality_(ZK_QUALITY),
        safe_modulus_proof_() {}

  void SetUp() override {
    safe_modulus_proof_ =
        std::make_unique<PedersenOverZn::ProofOfGenForTrustedModulus>(
            PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
                &ctx_, g_, h_, n_, r_, challenge_length_, zk_quality_)
                .value());
  }

  Context ctx_;
  BigNum g_;
  BigNum h_;
  BigNum n_;
  BigNum r_;
  int challenge_length_;
  int zk_quality_;
  std::unique_ptr<PedersenOverZn::ProofOfGenForTrustedModulus>
      safe_modulus_proof_;
};

TEST_F(PedersenOverZnGenProofForTrustedModulusTest, TestHonestProofVerifies) {
  EXPECT_TRUE(PedersenOverZn::VerifyParamsProofForTrustedModulus(
                  &ctx_, g_, h_, n_, *safe_modulus_proof_)
                  .ok());
}

TEST_F(PedersenOverZnGenProofForTrustedModulusTest,
       TestProofGenerationFailsOnInvalidInputs) {
  auto maybe_result =
      PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
          &ctx_, g_, h_, n_, r_, 0, zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("challenge length must be positive."));

  maybe_result =
      PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
          &ctx_, g_, h_, n_, r_, challenge_length_, 0);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("zk_quality parameter must be positive."));

  maybe_result =
      PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
          &ctx_, g_, ctx_.CreateBigNum(20), n_, r_, challenge_length_,
          zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(),
              HasSubstr("h is not relatively prime to n."));

  maybe_result =
      PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
          &ctx_, ctx_.CreateBigNum(2), h_, n_, r_, challenge_length_,
          zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(), HasSubstr("g != h^r mod n."));

  maybe_result =
      PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
          &ctx_, g_, h_, n_, ctx_.CreateBigNum(2), challenge_length_,
          zk_quality_);
  EXPECT_TRUE(IsInvalidArgument(maybe_result.status()));
  EXPECT_THAT(maybe_result.status().message(), HasSubstr("g != h^r mod n."));
}

TEST_F(PedersenOverZnGenProofForTrustedModulusTest,
       TestProofVerificationFailsOnInvalidInputs) {
  Status status;
  // Proof contains invalid challenge length
  safe_modulus_proof_->challenge_length = 0;
  status = PedersenOverZn::VerifyParamsProofForTrustedModulus(
      &ctx_, g_, h_, n_, *safe_modulus_proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("challenge length must be positive."));
  safe_modulus_proof_->challenge_length = CHALLENGE_LENGTH;

  // h is not relatively prime to modulus.
  status = PedersenOverZn::VerifyParamsProofForTrustedModulus(
      &ctx_, g_, ctx_.CreateBigNum(20), n_, *safe_modulus_proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("h is not relatively prime to n."));
}

TEST_F(PedersenOverZnGenProofForTrustedModulusTest,
       TestProofVerificationFailsOnIncorrectProof) {
  Status status;
  // Change g to g+1
  status = PedersenOverZn::VerifyParamsProofForTrustedModulus(
      &ctx_, g_ + ctx_.One(), h_, n_, *safe_modulus_proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("the proof verification formula fails."));

  // Change dummy_g
  safe_modulus_proof_->dummy_g = safe_modulus_proof_->dummy_g + ctx_.One();
  status = PedersenOverZn::VerifyParamsProofForTrustedModulus(
      &ctx_, g_, h_, n_, *safe_modulus_proof_);
  EXPECT_TRUE(IsInvalidArgument(status));
  EXPECT_THAT(status.message(),
              ::testing::HasSubstr("the proof verification formula fails."));
}

}  // namespace
}  // namespace private_join_and_compute
