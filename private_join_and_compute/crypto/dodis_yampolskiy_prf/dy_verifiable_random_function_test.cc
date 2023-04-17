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

#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.pb.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using testing::IsOkAndHolds;
using testing::StatusIs;

const int kTestCurveId = NID_X9_62_prime256v1;
const int kSafePrimeLengthBits = 600;
const int kSecurityParameter = 128;
const int kChallengeLengthBits = 128;

class DyVerifiableRandomFunctionTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    Context ctx;
    BigNum prime = ctx.GenerateSafePrime(kSafePrimeLengthBits);
    serialized_safe_prime_ = new std::string(prime.ToBytes());
  }

  static void TearDownTestSuite() { delete serialized_safe_prime_; }

  struct Transcript {
    std::vector<ECPoint> prf_evaluations;
    PedersenOverZn::CommitmentAndOpening commit_and_open_messages;
    proto::DyVrfApplyProof apply_proof;
    BigNum challenge;
  };

  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(auto ec_group_do_not_use_later,
                         ECGroup::Create(kTestCurveId, &ctx_));
    ec_group_ = std::make_unique<ECGroup>(std::move(ec_group_do_not_use_later));

    // We generate a Pedersen with fixed bases 2, 3, 5 and h=7, and use a random
    // safe prime as N.
    std::vector<BigNum> bases = {ctx_.CreateBigNum(2), ctx_.CreateBigNum(3),
                                 ctx_.CreateBigNum(5)};
    pedersen_parameters_.set_n(*serialized_safe_prime_);
    *pedersen_parameters_.mutable_gs() = BigNumVectorToProto(bases);
    pedersen_parameters_.set_h(ctx_.CreateBigNum(7).ToBytes());
    ASSERT_OK_AND_ASSIGN(
        pedersen_, PedersenOverZn::FromProto(&ctx_, pedersen_parameters_));

    // All other params are set to the defaults.
    parameters_.set_security_parameter(kSecurityParameter);
    parameters_.set_challenge_length_bits(kChallengeLengthBits);
    dy_prf_base_g_ =
        std::make_unique<ECPoint>(ec_group_->GetRandomGenerator().value());
    ASSERT_OK_AND_ASSIGN(*parameters_.mutable_dy_prf_base_g(),
                         dy_prf_base_g_->ToBytesCompressed());
    *parameters_.mutable_pedersen_parameters() = pedersen_parameters_;

    ASSERT_OK_AND_ASSIGN(
        dy_vrf_, DyVerifiableRandomFunction::Create(
                     parameters_, &ctx_, ec_group_.get(), pedersen_.get()));

    std::tie(public_key_, private_key_, std::ignore) =
        dy_vrf_->GenerateKeyPair().value();
  }

  StatusOr<Transcript> GenerateTranscript(const std::vector<BigNum>& messages) {
    // Apply the PRF.
    ASSIGN_OR_RETURN(std::vector<ECPoint> prf_evaluations,
                     dy_vrf_->Apply(messages, private_key_));

    // Commit to the messages.
    ASSIGN_OR_RETURN(
        PedersenOverZn::CommitmentAndOpening commit_and_open_messages,
        pedersen_->Commit(messages));

    // Generate the proof.
    ASSIGN_OR_RETURN(
        proto::DyVrfApplyProof apply_proof,
        dy_vrf_->GenerateApplyProof(messages, prf_evaluations, public_key_,
                                    private_key_, commit_and_open_messages));

    // Regenerate the challenge.
    ASSIGN_OR_RETURN(BigNum challenge, dy_vrf_->GenerateApplyProofChallenge(
                                           prf_evaluations, public_key_,
                                           commit_and_open_messages.commitment,
                                           apply_proof.message_1()));

    return Transcript{std::move(prf_evaluations),
                      std::move(commit_and_open_messages),
                      std::move(apply_proof), std::move(challenge)};
  }

  // Shared across tests, generated once
  static std::string* serialized_safe_prime_;

  Context ctx_;
  std::unique_ptr<ECGroup> ec_group_;
  proto::PedersenParameters pedersen_parameters_;
  std::unique_ptr<PedersenOverZn> pedersen_;

  std::unique_ptr<ECPoint> dy_prf_base_g_;
  proto::DyVrfParameters parameters_;
  std::unique_ptr<DyVerifiableRandomFunction> dy_vrf_;

  proto::DyVrfPublicKey public_key_;
  proto::DyVrfPrivateKey private_key_;
};

std::string* DyVerifiableRandomFunctionTest::serialized_safe_prime_ = nullptr;

TEST_F(DyVerifiableRandomFunctionTest,
       GenerateKeyPairProducesConsistentPublicKey) {
  // Replicate the key for each Pedersen base.
  std::vector<BigNum> key_vector(pedersen_->gs().size(),
                                 ctx_.CreateBigNum(private_key_.prf_key()));
  // Check that private and public key are consistent.
  EXPECT_THAT(
      pedersen_->CommitWithRand(
          key_vector, ctx_.CreateBigNum(private_key_.open_commit_prf_key())),
      IsOkAndHolds(Eq(ctx_.CreateBigNum(public_key_.commit_prf_key()))));
}

TEST_F(DyVerifiableRandomFunctionTest, GenerateKeyPairProducesDifferentValues) {
  ASSERT_OK_AND_ASSIGN(auto key_pair_1, dy_vrf_->GenerateKeyPair());
  ASSERT_OK_AND_ASSIGN(auto key_pair_2, dy_vrf_->GenerateKeyPair());

  // Check that private keys are different
  EXPECT_NE(std::get<1>(key_pair_1).prf_key(),
            std::get<1>(key_pair_2).prf_key());
  EXPECT_NE(std::get<1>(key_pair_1).open_commit_prf_key(),
            std::get<1>(key_pair_2).open_commit_prf_key());
}

TEST_F(DyVerifiableRandomFunctionTest, GenerateKeyProofSucceeds) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  EXPECT_OK(dy_vrf_->VerifyGenerateKeysProof(public_key_proto,
                                             generate_keys_proof_proto));
}

TEST_F(DyVerifiableRandomFunctionTest, EmptyGenerateKeyProofFails) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  // Empty proof should fail.
  EXPECT_THAT(
      dy_vrf_->VerifyGenerateKeysProof(public_key_proto,
                                       proto::DyVrfGenerateKeysProof()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(DyVerifiableRandomFunctionTest, GenerateKeyProofFailsForDifferentKeys) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  // Using this proof with the keys generated by the test fixture should fail.
  EXPECT_THAT(
      dy_vrf_->VerifyGenerateKeysProof(public_key_, generate_keys_proof_proto),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       GenerateKeyProofFailsWhenPrfCommitmentIsMissing) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  public_key_proto.clear_commit_prf_key();
  // Technically this proof fails because the verification method fails to
  // compute a modular inverse.
  EXPECT_THAT(
      dy_vrf_->VerifyGenerateKeysProof(public_key_proto,
                                       generate_keys_proof_proto),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Inverse")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       GenerateKeyProofFailsWhenMaskedDummyPrfKeyIsTooLarge) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  BigNum too_large =
      ctx_.CreateBigNum(
              generate_keys_proof_proto.message_2().masked_dummy_prf_key())
          .Lshift(20);

  generate_keys_proof_proto.mutable_message_2()->set_masked_dummy_prf_key(
      too_large.ToBytes());

  EXPECT_THAT(dy_vrf_->VerifyGenerateKeysProof(public_key_proto,
                                               generate_keys_proof_proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("masked_dummy_prf_key")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       GenerateKeyProofFailsWhenMaskedDummyPrfKeyOpeningIsMissing) {
  proto::DyVrfPublicKey public_key_proto;
  proto::DyVrfPrivateKey private_key_proto;
  proto::DyVrfGenerateKeysProof generate_keys_proof_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(public_key_proto, private_key_proto, generate_keys_proof_proto),
      dy_vrf_->GenerateKeyPair());

  generate_keys_proof_proto.mutable_message_2()->clear_masked_dummy_prf_key();

  EXPECT_THAT(
      dy_vrf_->VerifyGenerateKeysProof(public_key_proto,
                                       generate_keys_proof_proto),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(DyVerifiableRandomFunctionTest, ApplySucceeds) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0),
                                  ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1),
                                  ctx_.CreateBigNum(0),
                                  ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(std::vector<ECPoint> prf_evaluations,
                       dy_vrf_->Apply(messages, private_key_));

  // Check that different values have different outputs
  EXPECT_NE(prf_evaluations[0], prf_evaluations[1]);
  EXPECT_NE(prf_evaluations[0], prf_evaluations[2]);
  EXPECT_NE(prf_evaluations[1], prf_evaluations[2]);

  // Check that the same value has the same output.
  EXPECT_EQ(prf_evaluations[0], prf_evaluations[3]);
  EXPECT_EQ(prf_evaluations[1], prf_evaluations[4]);
  EXPECT_EQ(prf_evaluations[2], prf_evaluations[5]);

  BigNum prf_key = ctx_.CreateBigNum(private_key_.prf_key());
  // Check the concrete value of the outputs.
  for (size_t i = 0; i < prf_evaluations.size(); ++i) {
    BigNum message_plus_key = messages[i] + prf_key;
    EXPECT_EQ(prf_evaluations[i].Mul(message_plus_key).value(),
              *dy_prf_base_g_);
  }
}

TEST_F(DyVerifiableRandomFunctionTest, ProofSucceedsEndToEnd) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  // Apply the PRF.
  ASSERT_OK_AND_ASSIGN(std::vector<ECPoint> prf_evaluations,
                       dy_vrf_->Apply(messages, private_key_));

  // Commit to the messages.
  ASSERT_OK_AND_ASSIGN(
      PedersenOverZn::CommitmentAndOpening commit_and_open_messages,
      pedersen_->Commit(messages));

  // Generate the proof.
  ASSERT_OK_AND_ASSIGN(
      proto::DyVrfApplyProof apply_proof,
      dy_vrf_->GenerateApplyProof(messages, prf_evaluations, public_key_,
                                  private_key_, commit_and_open_messages));
  // Verify the result
  EXPECT_OK(dy_vrf_->VerifyApplyProof(prf_evaluations, public_key_,
                                      commit_and_open_messages.commitment,
                                      apply_proof));
}

TEST_F(DyVerifiableRandomFunctionTest, SucceedsWithFewerMessagesThanBases) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(5)};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  // Verify the result
  EXPECT_OK(dy_vrf_->VerifyApplyProof(
      transcript.prf_evaluations, public_key_,
      transcript.commit_and_open_messages.commitment, transcript.apply_proof));
}

// The test with too many messages is skipped because it fails when trying to
// create the Pedersen commitment before GenerateApplyProof is called.

TEST_F(DyVerifiableRandomFunctionTest, ProofFailsOnChangedMessages) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  std::vector<BigNum> wrong_messages = {
      ctx_.CreateBigNum(2), ctx_.CreateBigNum(3), ctx_.CreateBigNum(7)};

  // Apply the PRF to wrong_messages.
  ASSERT_OK_AND_ASSIGN(std::vector<ECPoint> wrong_prf_evaluations,
                       dy_vrf_->Apply(wrong_messages, private_key_));

  // Expect the verification fails.
  EXPECT_THAT(
      dy_vrf_->VerifyApplyProof(wrong_prf_evaluations, public_key_,
                                transcript.commit_and_open_messages.commitment,
                                transcript.apply_proof),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

TEST_F(DyVerifiableRandomFunctionTest, ProofFailsIfRoPrefixIsChanged) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  proto::DyVrfParameters modified_parameters = parameters_;
  modified_parameters.set_random_oracle_prefix("modified");

  ASSERT_OK_AND_ASSIGN(
      auto modified_dy_vrf,
      DyVerifiableRandomFunction::Create(modified_parameters, &ctx_,
                                         ec_group_.get(), pedersen_.get()));

  // Expect the verification fails when using the modified parameters.
  EXPECT_THAT(modified_dy_vrf->VerifyApplyProof(
                  transcript.prf_evaluations, public_key_,
                  transcript.commit_and_open_messages.commitment,
                  transcript.apply_proof),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

TEST_F(DyVerifiableRandomFunctionTest, ChallengeIsCorrectlyBounded) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  EXPECT_LE(transcript.challenge, ctx_.One().Lshift(kChallengeLengthBits));
}

TEST_F(DyVerifiableRandomFunctionTest, ChallengeChangesOnWrongMessages) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  std::vector<BigNum> wrong_messages = {
      ctx_.CreateBigNum(2), ctx_.CreateBigNum(3), ctx_.CreateBigNum(7)};

  // Apply the PRF to wrong_messages.
  ASSERT_OK_AND_ASSIGN(std::vector<ECPoint> wrong_prf_evaluations,
                       dy_vrf_->Apply(wrong_messages, private_key_));

  // Expect the challenge changes.
  ASSERT_OK_AND_ASSIGN(BigNum challenge_2,
                       dy_vrf_->GenerateApplyProofChallenge(
                           wrong_prf_evaluations, public_key_,
                           transcript.commit_and_open_messages.commitment,
                           transcript.apply_proof.message_1()));

  EXPECT_NE(transcript.challenge, challenge_2);
}

TEST_F(DyVerifiableRandomFunctionTest,
       DifferentTranscriptsHaveDifferentChallenges) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  EXPECT_NE(transcript_1.challenge, transcript_2.challenge);
}

TEST_F(DyVerifiableRandomFunctionTest, ProofFailsWhenMessage1Deleted) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  transcript.apply_proof.clear_message_1();

  EXPECT_THAT(
      dy_vrf_->VerifyApplyProof(transcript.prf_evaluations, public_key_,
                                transcript.commit_and_open_messages.commitment,
                                transcript.apply_proof),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("different")));
}

TEST_F(DyVerifiableRandomFunctionTest, ProofFailsWhenMessage2Deleted) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  transcript.apply_proof.clear_message_2();

  EXPECT_THAT(
      dy_vrf_->VerifyApplyProof(transcript.prf_evaluations, public_key_,
                                transcript.commit_and_open_messages.commitment,
                                transcript.apply_proof),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("different")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       ProofFailsWhenCommitDummyMessagesPlusKeySwapped) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  *transcript_1.apply_proof.mutable_message_1()
       ->mutable_commit_dummy_messages_plus_key() =
      transcript_2.apply_proof.message_1().commit_dummy_messages_plus_key();

  EXPECT_THAT(dy_vrf_->VerifyApplyProof(
                  transcript_1.prf_evaluations, public_key_,
                  transcript_1.commit_and_open_messages.commitment,
                  transcript_1.apply_proof),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

TEST_F(DyVerifiableRandomFunctionTest, ProofFailsWhenDummyDyPrfBaseGSSwapped) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  *transcript_1.apply_proof.mutable_message_1()
       ->mutable_dummy_dy_prf_base_gs() =
      transcript_2.apply_proof.message_1().dummy_dy_prf_base_gs();

  EXPECT_THAT(dy_vrf_->VerifyApplyProof(
                  transcript_1.prf_evaluations, public_key_,
                  transcript_1.commit_and_open_messages.commitment,
                  transcript_1.apply_proof),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       ProofFailsWhenMaskedDummyMessagesPlusKeySwapped) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  *transcript_1.apply_proof.mutable_message_2()
       ->mutable_masked_dummy_messages_plus_key() =
      transcript_2.apply_proof.message_2().masked_dummy_messages_plus_key();

  EXPECT_THAT(dy_vrf_->VerifyApplyProof(
                  transcript_1.prf_evaluations, public_key_,
                  transcript_1.commit_and_open_messages.commitment,
                  transcript_1.apply_proof),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

TEST_F(DyVerifiableRandomFunctionTest,
       ProofFailsWhenMaskedDummyOpeningSwapped) {
  std::vector<BigNum> messages = {ctx_.CreateBigNum(0), ctx_.CreateBigNum(5),
                                  ec_group_->GetOrder() - ctx_.CreateBigNum(1)};

  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  *transcript_1.apply_proof.mutable_message_2()
       ->mutable_masked_dummy_opening() =
      transcript_2.apply_proof.message_2().masked_dummy_opening();

  EXPECT_THAT(dy_vrf_->VerifyApplyProof(
                  transcript_1.prf_evaluations, public_key_,
                  transcript_1.commit_and_open_messages.commitment,
                  transcript_1.apply_proof),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("fail")));
}

}  // namespace
}  // namespace private_join_and_compute
