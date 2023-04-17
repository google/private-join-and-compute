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

#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/camenisch_shoup.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.pb.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status_testing.inc"
namespace private_join_and_compute {
namespace {

using ::testing::HasSubstr;
using testing::StatusIs;

const int kTestCurveId = NID_X9_62_prime256v1;
const int kSafePrimeLengthBits = 768;
const int kChallengeLengthBits = 128;
const int kSecurityParameter = 128;
const int kCamenischShoupS = 1;

// Different test cases for combinations of parameters.
struct BbObliviousSignatureTestCase {
  std::string name;
  int num_messages;
  // should be >= num_messages.
  int num_pedersen_bases;
  int camenisch_shoup_vector_encryption_length;
};

class BbObliviousSignatureTest
    : public ::testing::TestWithParam<BbObliviousSignatureTestCase> {
 protected:
  static void SetUpTestSuite() {
    Context ctx;
    BigNum p = ctx.GenerateSafePrime(kSafePrimeLengthBits);
    serialized_safe_prime_p_ = new std::string(p.ToBytes());
    BigNum q = ctx.GenerateSafePrime(kSafePrimeLengthBits);
    serialized_safe_prime_q_ = new std::string(p.ToBytes());
  }

  static void TearDownTestSuite() {
    delete serialized_safe_prime_p_;
    delete serialized_safe_prime_q_;
  }

  void SetUp() override {
    const BbObliviousSignatureTestCase& test_case = GetParam();
    num_messages_ = test_case.num_messages;
    num_pedersen_bases_ = test_case.num_pedersen_bases;
    camenisch_shoup_vector_encryption_length_ =
        test_case.camenisch_shoup_vector_encryption_length;

    ASSERT_OK_AND_ASSIGN(auto ec_group_do_not_use_later,
                         ECGroup::Create(kTestCurveId, &ctx_));
    ec_group_ = std::make_unique<ECGroup>(std::move(ec_group_do_not_use_later));

    BigNum p = ctx_.CreateBigNum(*serialized_safe_prime_p_);
    BigNum q = ctx_.CreateBigNum(*serialized_safe_prime_q_);
    BigNum n = p * q;

    // All other params are set to the defaults.
    params_proto_.set_challenge_length_bits(kChallengeLengthBits);
    params_proto_.set_security_parameter(kSecurityParameter);
    base_g_ =
        std::make_unique<ECPoint>(ec_group_->GetRandomGenerator().value());
    params_proto_.set_base_g(base_g_->ToBytesCompressed().value());

    // Generate Pedersen Parameters
    PedersenOverZn::Parameters pedersen_parameters_struct =
        PedersenOverZn::GenerateParameters(&ctx_, n,
                                           test_case.num_pedersen_bases);
    proto::PedersenParameters pedersen_params =
        PedersenOverZn::ParametersToProto(pedersen_parameters_struct);

    *params_proto_.mutable_pedersen_parameters() = pedersen_params;
    ASSERT_OK_AND_ASSIGN(pedersen_,
                         PedersenOverZn::FromProto(&ctx_, pedersen_params));

    std::tie(cs_public_key_, cs_private_key_) = GenerateCamenischShoupKeyPair(
        &ctx_, n, kCamenischShoupS,
        test_case.camenisch_shoup_vector_encryption_length);

    *params_proto_.mutable_camenisch_shoup_public_key() =
        CamenischShoupPublicKeyToProto(*cs_public_key_);

    ASSERT_OK_AND_ASSIGN(
        public_camenisch_shoup_,
        PublicCamenischShoup::FromProto(
            &ctx_, params_proto_.camenisch_shoup_public_key()));
    private_camenisch_shoup_ = std::make_unique<PrivateCamenischShoup>(
        &ctx_, cs_public_key_->n, cs_public_key_->s, cs_public_key_->g,
        cs_public_key_->ys, cs_private_key_->xs);

    ASSERT_OK_AND_ASSIGN(bb_ob_sig_,
                         BbObliviousSignature::Create(
                             params_proto_, &ctx_, ec_group_.get(),
                             public_camenisch_shoup_.get(), pedersen_.get()));
    ASSERT_OK_AND_ASSIGN(std::tie(public_key_proto_, private_key_proto_),
                         bb_ob_sig_->GenerateKeys());

    k_ = std::make_unique<BigNum>(ctx_.CreateBigNum(private_key_proto_.k()));
    y_ = std::make_unique<BigNum>(ctx_.CreateBigNum(private_key_proto_.y()));
  }

  // Generates random messages appropriate for a signature request.
  std::vector<BigNum> GenerateRandomMessages(int num_messages) {
    std::vector<BigNum> messages;
    messages.reserve(num_messages);
    for (int i = 0; i < num_messages; ++i) {
      messages.push_back(ec_group_->GeneratePrivateKey());
    }
    return messages;
  }

  // Holds a transcript for a Oblivious Signature request.
  struct Transcript {
    std::unique_ptr<PedersenOverZn::CommitmentAndOpening>
        commit_and_open_messages;
    std::vector<BigNum> rs;
    std::unique_ptr<PedersenOverZn::CommitmentAndOpening> commit_and_open_rs;
    proto::BbObliviousSignatureRequest request_proto;
    proto::BbObliviousSignatureRequestPrivateState request_private_state_proto;
    proto::BbObliviousSignatureRequestProof request_proof_proto;
    proto::BbObliviousSignatureResponse response_proto;
    proto::BbObliviousSignatureResponseProof response_proof_proto;
    std::vector<ECPoint> results;
  };

  // Generates an end-to-end request transcript. Does not verify request or
  // response proofs.
  StatusOr<Transcript> GenerateTranscript(const std::vector<BigNum>& messages) {
    Transcript transcript;

    ASSIGN_OR_RETURN(
        PedersenOverZn::CommitmentAndOpening commit_and_open_messages_temp,
        pedersen_->Commit(messages));
    transcript.commit_and_open_messages =
        std::make_unique<PedersenOverZn::CommitmentAndOpening>(
            std::move(commit_and_open_messages_temp));

    transcript.rs.reserve(messages.size());
    for (size_t i = 0; i < messages.size(); ++i) {
      transcript.rs.push_back(ec_group_->GeneratePrivateKey());
    }
    ASSIGN_OR_RETURN(
        PedersenOverZn::CommitmentAndOpening commit_and_open_rs_temp,
        pedersen_->Commit(transcript.rs));
    transcript.commit_and_open_rs =
        std::make_unique<PedersenOverZn::CommitmentAndOpening>(
            std::move(commit_and_open_rs_temp));

    // Create request
    ASSIGN_OR_RETURN(
        std::tie(transcript.request_proto, transcript.request_proof_proto,
                 transcript.request_private_state_proto),
        bb_ob_sig_->GenerateRequestAndProof(
            messages, transcript.rs, public_key_proto_,
            *transcript.commit_and_open_messages,
            *transcript.commit_and_open_rs));

    // Compute response
    ASSIGN_OR_RETURN(
        std::tie(transcript.response_proto, transcript.response_proof_proto),
        bb_ob_sig_->GenerateResponseAndProof(
            transcript.request_proto, public_key_proto_, private_key_proto_,
            transcript.commit_and_open_messages->commitment,
            transcript.commit_and_open_rs->commitment,
            private_camenisch_shoup_.get()));

    // Extract results
    ASSIGN_OR_RETURN(transcript.results,
                     bb_ob_sig_->ExtractResults(
                         transcript.response_proto, transcript.request_proto,
                         transcript.request_private_state_proto));

    return std::move(transcript);
  }

  // Shared across tests, generated once. We need to store p and q serialized,
  // as BigNum is always tied to a Context, which does not persist across tests.
  static std::string* serialized_safe_prime_p_;
  static std::string* serialized_safe_prime_q_;

  int num_messages_;
  int num_pedersen_bases_;
  int camenisch_shoup_vector_encryption_length_;

  proto::BbObliviousSignatureParameters params_proto_;

  Context ctx_;
  std::unique_ptr<ECGroup> ec_group_;
  std::unique_ptr<PedersenOverZn> pedersen_;

  std::unique_ptr<ECPoint> base_g_;
  std::unique_ptr<BbObliviousSignature> bb_ob_sig_;

  proto::BbObliviousSignaturePublicKey public_key_proto_;
  proto::BbObliviousSignaturePrivateKey private_key_proto_;

  std::unique_ptr<BigNum> k_;
  std::unique_ptr<BigNum> y_;

  std::unique_ptr<CamenischShoupPublicKey> cs_public_key_;
  std::unique_ptr<CamenischShoupPrivateKey> cs_private_key_;

  std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup_;
  std::unique_ptr<PrivateCamenischShoup> private_camenisch_shoup_;
};

std::string* BbObliviousSignatureTest::serialized_safe_prime_p_ = nullptr;
std::string* BbObliviousSignatureTest::serialized_safe_prime_q_ = nullptr;

TEST_P(BbObliviousSignatureTest,
       CreateFailsWhenPublicCamenischShoupNotLargeEnough) {
  // Create an "n" with a smaller modulus.
  int small_prime_length_bits = 256;
  BigNum p = ctx_.GenerateSafePrime(small_prime_length_bits);
  BigNum q = ctx_.GenerateSafePrime(small_prime_length_bits);
  BigNum small_n = p * q;

  proto::BbObliviousSignatureParameters small_params(params_proto_);

  // Generate a new Camenisch-Shoup encryption key consistent with those params.
  std::unique_ptr<CamenischShoupPublicKey> small_cs_public_key;
  std::unique_ptr<CamenischShoupPrivateKey> small_cs_private_key;
  std::unique_ptr<PublicCamenischShoup> small_public_camenisch_shoup;
  std::tie(small_cs_public_key, small_cs_private_key) =
      GenerateCamenischShoupKeyPair(&ctx_, small_n, kCamenischShoupS,
                                    camenisch_shoup_vector_encryption_length_);

  *small_params.mutable_camenisch_shoup_public_key() =
      CamenischShoupPublicKeyToProto(*small_cs_public_key);

  ASSERT_OK_AND_ASSIGN(small_public_camenisch_shoup,
                       PublicCamenischShoup::FromProto(
                           &ctx_, small_params.camenisch_shoup_public_key()));

  EXPECT_THAT(BbObliviousSignature::Create(small_params, &ctx_, ec_group_.get(),
                                           small_public_camenisch_shoup.get(),
                                           pedersen_.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not large enough")));
}

TEST_P(BbObliviousSignatureTest, CreateFailsWhenPedersenNotLargeEnough) {
  // Create an "n" with a smaller modulus.
  int small_prime_length_bits = 256;
  BigNum p = ctx_.GenerateSafePrime(small_prime_length_bits);
  BigNum q = ctx_.GenerateSafePrime(small_prime_length_bits);
  BigNum small_n = p * q;

  // Change the pedersen params to use the smaller modulus.
  *params_proto_.mutable_pedersen_parameters() =
      PedersenOverZn::ParametersToProto(PedersenOverZn::GenerateParameters(
          &ctx_, small_n, num_pedersen_bases_));
  // Reset the pedersen object with the updated params.
  ASSERT_OK_AND_ASSIGN(
      pedersen_,
      PedersenOverZn::FromProto(&ctx_, params_proto_.pedersen_parameters()));

  EXPECT_THAT(BbObliviousSignature::Create(
                  params_proto_, &ctx_, ec_group_.get(),
                  public_camenisch_shoup_.get(), pedersen_.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not large enough")));
}

TEST_P(BbObliviousSignatureTest, EvaluatesCorrectlyNoProofs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Validate results.
  EXPECT_EQ(transcript.results.size(), messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    ASSERT_OK_AND_ASSIGN(
        ECPoint expected_eval,
        base_g_->Mul((messages[i] + *k_ + (transcript.rs[i] * *y_))
                         .ModInverse(ec_group_->GetOrder())
                         .value()));
    EXPECT_EQ(transcript.results[i], expected_eval);
  }
}

TEST_P(BbObliviousSignatureTest, EvaluatesCorrectlyWithFewerMessagesNoProofs) {
  std::vector<BigNum> fewer_messages = GenerateRandomMessages(1);
  ASSERT_OK_AND_ASSIGN(Transcript transcript,
                       GenerateTranscript(fewer_messages));

  // Validate results.
  EXPECT_EQ(transcript.results.size(), fewer_messages.size());
  for (size_t i = 0; i < fewer_messages.size(); ++i) {
    ASSERT_OK_AND_ASSIGN(
        ECPoint expected_eval,
        base_g_->Mul((fewer_messages[i] + *k_ + (transcript.rs[i] * *y_))
                         .ModInverse(ec_group_->GetOrder())
                         .value()));
    EXPECT_EQ(transcript.results[i], expected_eval);
  }
}

TEST_P(BbObliviousSignatureTest, KeysEncryptsVectorOfSecret) {
  EXPECT_EQ(camenisch_shoup_vector_encryption_length_,
            public_key_proto_.encrypted_k_size());
  EXPECT_EQ(camenisch_shoup_vector_encryption_length_,
            public_key_proto_.encrypted_y_size());

  for (int i = 0; i < camenisch_shoup_vector_encryption_length_; ++i) {
    ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext encrypted_k_at_i,
                         public_camenisch_shoup_->ParseCiphertextProto(
                             public_key_proto_.encrypted_k(i)));
    ASSERT_OK_AND_ASSIGN(std::vector<BigNum> decrypted_k_at_i,
                         private_camenisch_shoup_->Decrypt(encrypted_k_at_i));
    ASSERT_OK_AND_ASSIGN(CamenischShoupCiphertext encrypted_y_at_i,
                         public_camenisch_shoup_->ParseCiphertextProto(
                             public_key_proto_.encrypted_y(i)));
    ASSERT_OK_AND_ASSIGN(std::vector<BigNum> decrypted_y_at_i,
                         private_camenisch_shoup_->Decrypt(encrypted_y_at_i));

    EXPECT_EQ(decrypted_k_at_i.size(),
              camenisch_shoup_vector_encryption_length_);
    EXPECT_EQ(decrypted_y_at_i.size(),
              camenisch_shoup_vector_encryption_length_);

    for (int j = 0; j < camenisch_shoup_vector_encryption_length_; ++j) {
      // Each should be equal to the secret key at the i'th position, and 0
      // elsewhere.
      if (j != i) {
        EXPECT_EQ(decrypted_k_at_i[j], ctx_.Zero());
        EXPECT_EQ(decrypted_y_at_i[j], ctx_.Zero());
      } else {
        EXPECT_EQ(decrypted_k_at_i[j], *k_);
        EXPECT_EQ(decrypted_y_at_i[j], *y_);
      }
    }
  }
}

TEST_P(BbObliviousSignatureTest, GeneratesDistinctYAndK) {
  EXPECT_NE(*k_, *y_);
}

TEST_P(BbObliviousSignatureTest, GeneratesDifferentKeys) {
  proto::BbObliviousSignaturePublicKey other_public_key_proto;
  proto::BbObliviousSignaturePrivateKey other_private_key_proto;
  ASSERT_OK_AND_ASSIGN(
      std::tie(other_public_key_proto, other_private_key_proto),
      bb_ob_sig_->GenerateKeys());

  EXPECT_NE(private_key_proto_.k(), other_private_key_proto.k());
  EXPECT_NE(private_key_proto_.y(), other_private_key_proto.y());
}

TEST_P(BbObliviousSignatureTest, RequestFailsWhenNumMessagesTooLarge) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Change messages to have one extra message (note that the messages vector is
  // inconsistent with the commitment, which is just for the purposes of this
  // test).
  messages.push_back(ctx_.Three());

  // Generating the request should fail.
  EXPECT_THAT(
      bb_ob_sig_->GenerateRequestAndProof(
          messages, transcript.rs, public_key_proto_,
          *transcript.commit_and_open_messages, *transcript.commit_and_open_rs),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("messages has size")));
}

TEST_P(BbObliviousSignatureTest,
       RequestFailsWhenRsHasDifferentLengthFromMessages) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Change rs to have one less message, and recommit.
  transcript.rs.pop_back();
  ASSERT_OK_AND_ASSIGN(
      PedersenOverZn::CommitmentAndOpening commit_and_open_rs_temp,
      pedersen_->Commit(transcript.rs));
  transcript.commit_and_open_rs =
      std::make_unique<PedersenOverZn::CommitmentAndOpening>(
          std::move(commit_and_open_rs_temp));

  // Generating the request should fail.
  EXPECT_THAT(
      bb_ob_sig_->GenerateRequestAndProof(
          messages, transcript.rs, public_key_proto_,
          *transcript.commit_and_open_messages, *transcript.commit_and_open_rs),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("rs has size")));
}

TEST_P(BbObliviousSignatureTest, RequestsAreDifferent) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  EXPECT_NE(
      transcript_1.request_proto.repeated_encrypted_masked_messages(0).u(),
      transcript_2.request_proto.repeated_encrypted_masked_messages(0).u());
}

TEST_P(BbObliviousSignatureTest, ResponseFailsWhenNumMessagesIsTooLarge) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  transcript.request_proto.set_num_messages(messages.size() + 1);

  // Generating the request should fail.
  EXPECT_THAT(
      bb_ob_sig_->GenerateResponseAndProof(
          transcript.request_proto, public_key_proto_, private_key_proto_,
          transcript.commit_and_open_messages->commitment,
          transcript.commit_and_open_rs->commitment,
          private_camenisch_shoup_.get()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("num_messages")));
}

TEST_P(BbObliviousSignatureTest, ResponsesFromDifferentRequestsAreDifferent) {
  // Responses are actually generated deterministically from requests, so this
  // test is implicitly testing that the requests used different randomness.
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  EXPECT_NE(transcript_1.response_proto.masked_signature_values()
                .serialized_ec_points(0),
            transcript_2.response_proto.masked_signature_values()
                .serialized_ec_points(0));
}

////////////////////////////////////////////////////////////////////////////////
// Verify Request tests
////////////////////////////////////////////////////////////////////////////////

TEST_P(BbObliviousSignatureTest,
       VerifyRequestFailsWhenNumMessagesTooLargeForPedersen) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Modify num_messages to be too large.
  transcript.request_proto.set_num_messages(num_messages_ + 1);

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("messages has size")));
}

TEST_P(BbObliviousSignatureTest,
       VerifyRequestFailsWithEncryptedMaskedMessagesOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the encrypted_masked_messages.
  transcript.request_proto.mutable_repeated_encrypted_masked_messages()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("number of ciphertexts")));
}

TEST_P(BbObliviousSignatureTest, RequestProofSucceeds) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  EXPECT_OK(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment));
}

TEST_P(BbObliviousSignatureTest, RequestChallengeIsBounded) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));

  EXPECT_LE(ctx_.CreateBigNum(transcript.request_proof_proto.challenge()),
            ctx_.One().Lshift(kChallengeLengthBits));
}

TEST_P(BbObliviousSignatureTest, RequestChallengeChangesIfRoPrefixIsChanged) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));

  proto::BbObliviousSignatureParameters params_proto_2(params_proto_);
  params_proto_2.set_random_oracle_prefix("different_prefix");

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<BbObliviousSignature> bb_ob_sign_2,
                       BbObliviousSignature::Create(
                           params_proto_2, &ctx_, ec_group_.get(),
                           public_camenisch_shoup_.get(), pedersen_.get()));

  EXPECT_THAT(
      bb_ob_sign_2->VerifyRequest(
          public_key_proto_, transcript.request_proto,
          transcript.request_proof_proto,
          transcript.commit_and_open_messages->commitment,
          transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("challenge")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFromDifferentRequestHasDifferentChallenge) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(auto transcript_1, GenerateTranscript(messages));

  // Generate a second transcript
  ASSERT_OK_AND_ASSIGN(auto transcript_2, GenerateTranscript(messages));

  EXPECT_NE(transcript_1.request_proof_proto.challenge(),
            transcript_2.request_proof_proto.challenge());
}

TEST_P(BbObliviousSignatureTest, RquestProofFromDifferentRequestFails) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(auto transcript_1, GenerateTranscript(messages));

  // Generate a second transcript
  ASSERT_OK_AND_ASSIGN(auto transcript_2, GenerateTranscript(messages));

  // Use the request proof from the first request to validate the second.
  // Expect the verification to fail.
  EXPECT_THAT(bb_ob_sig_->VerifyRequest(
                  public_key_proto_, transcript_2.request_proto,
                  transcript_1.request_proof_proto,
                  transcript_2.commit_and_open_messages->commitment,
                  transcript_2.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("VerifyRequest: Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithCommitAsOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the commit_as.
  transcript.request_proof_proto.mutable_commit_as()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("commit_as")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyMessagesOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_messages.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_messages()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_messages")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyRsOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_rs.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_rs()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_rs")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyAsOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_as.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_as()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_as")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyBsOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_bs.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_bs()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_bs")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyAlphasOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_alphas.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_alphas()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_alphas")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyGammasOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the masked_dummy_gammas.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_gammas()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_gammas")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithMaskedDummyEncryptionRandomnessOfWrongSize) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  // Remove one of the encrypted_masked_messages.
  transcript.request_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_encryption_randomness_per_ciphertext()
      ->mutable_serialized_big_nums()
      ->RemoveLast();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("masked_dummy_encryption_randomness")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongCommitBs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace commit_bs in the first transcript with that from the second.
  *transcript.request_proof_proto.mutable_commit_bs() =
      transcript_2.request_proof_proto.commit_bs();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongCommitAlphas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace commit_alphas in the first transcript with that from the second.
  *transcript.request_proof_proto.mutable_commit_alphas() =
      transcript_2.request_proof_proto.commit_alphas();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongCommitGammas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace commit_gammas in the first transcript with that from the second.
  *transcript.request_proof_proto.mutable_commit_gammas() =
      transcript_2.request_proof_proto.commit_gammas();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongChallenge) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace challenge in the first transcript with that from the second.
  *transcript.request_proof_proto.mutable_challenge() =
      transcript_2.request_proof_proto.challenge();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyMessages) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_messages in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_messages() =
      transcript_2.request_proof_proto.message_2().masked_dummy_messages();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongMaskedDummyRs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_rs in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_rs() =
      transcript_2.request_proof_proto.message_2().masked_dummy_rs();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongMaskedDummyAs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_as in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_as() =
      transcript_2.request_proof_proto.message_2().masked_dummy_as();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongMaskedDummyBs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_bs in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_bs() =
      transcript_2.request_proof_proto.message_2().masked_dummy_bs();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongMaskedDummyAlphas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_alphas in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_alphas() =
      transcript_2.request_proof_proto.message_2().masked_dummy_alphas();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithWrongMaskedDummyGammas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_gammas in the first transcript with that from the
  // second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_gammas() =
      transcript_2.request_proof_proto.message_2().masked_dummy_gammas();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyMessagesOpening) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_messages_opening in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_messages_opening(
          transcript_2.request_proof_proto.message_2()
              .masked_dummy_messages_opening());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyRsOpening) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_rs_opening in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_rs_opening(transcript_2.request_proof_proto.message_2()
                                        .masked_dummy_rs_opening());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyAsOpening) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_as_opening in the first transcript with that
  // from the second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_as_opening() =
      transcript_2.request_proof_proto.message_2().masked_dummy_as_opening();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyBsOpening) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_bs_opening in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_bs_opening(transcript_2.request_proof_proto.message_2()
                                        .masked_dummy_bs_opening());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyAlphasOpening1) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_alphas_opening_1 in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_alphas_opening_1(
          transcript_2.request_proof_proto.message_2()
              .masked_dummy_alphas_opening_1());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyAlphasOpening2) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_alphas_opening_2 in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_alphas_opening_2(
          transcript_2.request_proof_proto.message_2()
              .masked_dummy_alphas_opening_2());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyGammasOpening1) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_gammas_opening_1 in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_gammas_opening_1(
          transcript_2.request_proof_proto.message_2()
              .masked_dummy_gammas_opening_1());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyGammasOpening2) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_gammas_opening_2 in the first transcript with that
  // from the second.
  transcript.request_proof_proto.mutable_message_2()
      ->set_masked_dummy_gammas_opening_2(
          transcript_2.request_proof_proto.message_2()
              .masked_dummy_gammas_opening_2());

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest,
       RequestProofFailsWithWrongMaskedDummyEncryptionRandomness) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));

  // Replace masked_dummy_encryption_randomness in the first transcript with
  // that from the second.
  *transcript.request_proof_proto.mutable_message_2()
       ->mutable_masked_dummy_encryption_randomness_per_ciphertext() =
      transcript_2.request_proof_proto.message_2()
          .masked_dummy_encryption_randomness_per_ciphertext();

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_P(BbObliviousSignatureTest, RequestProofFailsWithEnormousMessages) {
  BigNum large_message =
      ec_group_->GetOrder() *
      ec_group_->GetOrder().Lshift(
          2 * (kChallengeLengthBits + kSecurityParameter + 1));

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript({large_message}));

  EXPECT_THAT(
      bb_ob_sig_->VerifyRequest(public_key_proto_, transcript.request_proto,
                                transcript.request_proof_proto,
                                transcript.commit_and_open_messages->commitment,
                                transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger")));
}

////////////////////////////////////////////////////////////////////////////////
// Verify Response tests
////////////////////////////////////////////////////////////////////////////////

TEST_P(BbObliviousSignatureTest, ResponseProofSucceeds) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  EXPECT_OK(bb_ob_sig_->VerifyResponse(
      public_key_proto_, transcript.response_proto,
      transcript.response_proof_proto, transcript.request_proto,
      transcript.commit_and_open_messages->commitment,
      transcript.commit_and_open_rs->commitment));
}

TEST_P(BbObliviousSignatureTest, ResponseChallengeIsBounded) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));

  EXPECT_LE(ctx_.CreateBigNum(transcript.response_proof_proto.challenge()),
            ctx_.One().Lshift(kChallengeLengthBits));
}

TEST_P(BbObliviousSignatureTest, ResponseChallengeChangesIfRoPrefixIsChanged) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));

  proto::BbObliviousSignatureParameters params_proto_2(params_proto_);
  params_proto_2.set_random_oracle_prefix("different_prefix");

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<BbObliviousSignature> bb_ob_sign_2,
                       BbObliviousSignature::Create(
                           params_proto_2, &ctx_, ec_group_.get(),
                           public_camenisch_shoup_.get(), pedersen_.get()));

  EXPECT_THAT(
      bb_ob_sign_2->VerifyResponse(
          public_key_proto_, transcript.response_proto,
          transcript.response_proof_proto, transcript.request_proto,
          transcript.commit_and_open_messages->commitment,
          transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("challenge")));
}

TEST_P(BbObliviousSignatureTest,
       ResponseProofFromDifferentRequestHasDifferentChallenge) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript_1, GenerateTranscript(messages));

  // Generate a second transcript
  ASSERT_OK_AND_ASSIGN(auto transcript_2, GenerateTranscript(messages));

  EXPECT_NE(transcript_1.response_proof_proto.challenge(),
            transcript_2.response_proof_proto.challenge());
}

TEST_P(BbObliviousSignatureTest, ResponseProofFromDifferentRequestFails) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript_1, GenerateTranscript(messages));

  // Generate a second transcript
  ASSERT_OK_AND_ASSIGN(auto transcript_2, GenerateTranscript(messages));

  // Use the response proof from the first request to validate the second.
  // Expect the verification to fail.
  EXPECT_THAT(bb_ob_sig_->VerifyResponse(
                  public_key_proto_, transcript_2.response_proto,
                  transcript_1.response_proof_proto, transcript_2.request_proto,
                  transcript_2.commit_and_open_messages->commitment,
                  transcript_2.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("VerifyResponse: Failed")));
}

TEST_P(BbObliviousSignatureTest,
       ResponseProofFailsWithTooFewMaskedSignatureValues) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));
  // Remove one of the masked_signature_values.
  transcript.response_proto.mutable_masked_signature_values()
      ->mutable_serialized_ec_points()
      ->RemoveLast();
  EXPECT_THAT(bb_ob_sig_->VerifyResponse(
                  public_key_proto_, transcript.response_proto,
                  transcript.response_proof_proto, transcript.request_proto,
                  transcript.commit_and_open_messages->commitment,
                  transcript.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("masked_signature_values")));
}

TEST_P(BbObliviousSignatureTest, ResponseProofFailsWithTooFewMaskedXs) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));
  // Remove one of the masked_xs.
  transcript.response_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_camenisch_shoup_xs()
      ->mutable_serialized_big_nums()
      ->RemoveLast();
  EXPECT_THAT(bb_ob_sig_->VerifyResponse(
                  public_key_proto_, transcript.response_proto,
                  transcript.response_proof_proto, transcript.request_proto,
                  transcript.commit_and_open_messages->commitment,
                  transcript.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("masked_dummy_camenisch_shoup_xs")));
}

TEST_P(BbObliviousSignatureTest, ResponseProofFailsWithTooFewMaskedBetas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);
  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript(messages));
  // Remove one of the masked_betas.
  transcript.response_proof_proto.mutable_message_2()
      ->mutable_masked_dummy_betas()
      ->mutable_serialized_big_nums()
      ->RemoveLast();
  EXPECT_THAT(bb_ob_sig_->VerifyResponse(
                  public_key_proto_, transcript.response_proto,
                  transcript.response_proof_proto, transcript.request_proto,
                  transcript.commit_and_open_messages->commitment,
                  transcript.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("masked_dummy_betas")));
}

TEST_P(BbObliviousSignatureTest, FailsWithWrongResponseProofCommitBetas) {
  std::vector<BigNum> messages = GenerateRandomMessages(num_messages_);

  ASSERT_OK_AND_ASSIGN(auto transcript_1, GenerateTranscript(messages));

  // Generate a second transcript
  ASSERT_OK_AND_ASSIGN(auto transcript_2, GenerateTranscript(messages));

  // Use the commit_betas in response proof from the first request to
  // validate the second. Expect the verification to fail.
  *transcript_2.response_proof_proto.mutable_commit_betas() =
      transcript_1.response_proof_proto.commit_betas();

  EXPECT_THAT(bb_ob_sig_->VerifyResponse(
                  public_key_proto_, transcript_2.response_proto,
                  transcript_2.response_proof_proto, transcript_2.request_proto,
                  transcript_2.commit_and_open_messages->commitment,
                  transcript_2.commit_and_open_rs->commitment),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("VerifyResponse: Failed")));
}

TEST_P(BbObliviousSignatureTest, ResponseProofFailsWithEnormousBeta) {
  BigNum large_message =
      ec_group_->GetOrder() *
      ec_group_->GetOrder().Lshift(
          2 * (kChallengeLengthBits + kSecurityParameter + 1));

  ASSERT_OK_AND_ASSIGN(auto transcript, GenerateTranscript({large_message}));

  // Note that the request proof should also fail due to the enormous message,
  // but we don't check it when generating the transcript, so the enormous
  // message passes through to the response.

  EXPECT_THAT(
      bb_ob_sig_->VerifyResponse(
          public_key_proto_, transcript.response_proto,
          transcript.response_proof_proto, transcript.request_proto,
          transcript.commit_and_open_messages->commitment,
          transcript.commit_and_open_rs->commitment),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger")));
}

INSTANTIATE_TEST_SUITE_P(
    BbObliviousSignatureTests, BbObliviousSignatureTest,
    ::testing::ValuesIn<BbObliviousSignatureTestCase>({
        {"pedersen_4_cs_4", /*num_messages=*/4, /*num_pedersen_bases=*/4,
         /*camenisch_shoup_vector_encryption_length=*/4},
        {"pedersen_4_cs_2", /*num_messages=*/4, /*num_pedersen_bases=*/4,
         /*camenisch_shoup_vector_encryption_length=*/2},
        {"pedersen_4_cs_3", /*num_messages=*/4, /*num_pedersen_bases=*/4,
         /*camenisch_shoup_vector_encryption_length=*/3},
    }),
    [](const ::testing::TestParamInfo<BbObliviousSignatureTest::ParamType>&
           info) { return info.param.name; });

}  // namespace
}  // namespace private_join_and_compute
