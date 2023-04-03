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

#include <stdint.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/camenisch_shoup.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.pb.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"

namespace private_join_and_compute {

StatusOr<std::unique_ptr<BbObliviousSignature>> BbObliviousSignature::Create(
    proto::BbObliviousSignatureParameters parameters_proto, Context* ctx,
    ECGroup* ec_group, PublicCamenischShoup* public_camenisch_shoup,
    PedersenOverZn* pedersen) {
  if (ctx == nullptr) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: The Context object is null.");
  }
  if (ec_group == nullptr) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: The ECGroup object is null.");
  }
  if (public_camenisch_shoup == nullptr) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: The PublicCamenischShoup object is "
        "null.");
  }
  if (pedersen == nullptr) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: The PedersenOverZn object is null.");
  }
  if (parameters_proto.security_parameter() <= 0) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: security_parameter must be positive.");
  }
  if (parameters_proto.challenge_length_bits() <= 0) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: challenge_length_bits must be "
        "positive.");
  }

  if (pedersen->gs().size() <
      public_camenisch_shoup->vector_encryption_length()) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::Create: The Pedersen object provided does not "
        "support the "
        "vector_commitment_length corresponding to the Camenisch Shoup "
        "encryption scheme.");
  }
  // dummy_masked_betas_bound is the largest value that should be encrypt-able
  // by the Camenisch-Shoup scheme.
  BigNum dummy_masked_betas_bound =
      ctx->One()
          .Lshift(2 * parameters_proto.challenge_length_bits() +
                  2 * parameters_proto.security_parameter() + 1)
          .Mul(ec_group->GetOrder())
          .Mul(ec_group->GetOrder())
          .Mul(ec_group->GetOrder());

  if (dummy_masked_betas_bound >
      public_camenisch_shoup->message_upper_bound()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignature::Create: Camenisch-Shoup encryption scheme is "
        "not large enough to handle the messages in the proofs. Max message "
        "size: ",
        public_camenisch_shoup->message_upper_bound().ToDecimalString(),
        ", message size needed for proof: ",
        dummy_masked_betas_bound.ToDecimalString()));
  }
  if (dummy_masked_betas_bound > pedersen->n()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignature::Create: Pedersen Modulus is "
        "not large enough to handle the messages in the proofs. Max message "
        "size: ",
        pedersen->n().ToDecimalString(), ", message size needed for proof: ",
        dummy_masked_betas_bound.ToDecimalString()));
  }

  ASSIGN_OR_RETURN(ECPoint base_g,
                   ec_group->CreateECPoint(parameters_proto.base_g()));

  return absl::WrapUnique(new BbObliviousSignature(
      std::move(parameters_proto), ctx, ec_group, std::move(base_g),
      public_camenisch_shoup, pedersen));
}

StatusOr<std::tuple<proto::BbObliviousSignaturePublicKey,
                    proto::BbObliviousSignaturePrivateKey>>
BbObliviousSignature::GenerateKeys() {
  proto::BbObliviousSignaturePublicKey public_key_proto;
  proto::BbObliviousSignaturePrivateKey private_key_proto;

  BigNum k = ec_group_->GeneratePrivateKey();
  BigNum y = ec_group_->GeneratePrivateKey();
  private_key_proto.set_k(k.ToBytes());
  private_key_proto.set_y(y.ToBytes());

  public_key_proto.mutable_encrypted_k()->Reserve(
      public_camenisch_shoup_->vector_encryption_length());
  public_key_proto.mutable_encrypted_y()->Reserve(
      public_camenisch_shoup_->vector_encryption_length());

  // The keys k and y should be encrypted vector_encryption_length times,
  // separately for each slot of the ciphertext.
  for (uint64_t i = 0; i < public_camenisch_shoup_->vector_encryption_length();
       ++i) {
    std::vector<BigNum> messages(
        public_camenisch_shoup_->vector_encryption_length(), ctx_->Zero());
    // Encrypt and push back k
    messages[i] = k;
    ASSIGN_OR_RETURN(CamenischShoupCiphertext k_ciphertext,
                     public_camenisch_shoup_->Encrypt(messages));
    *public_key_proto.add_encrypted_k() =
        CamenischShoupCiphertextToProto(k_ciphertext);
    // Encrypt and push back y
    messages[i] = y;
    ASSIGN_OR_RETURN(CamenischShoupCiphertext y_ciphertext,
                     public_camenisch_shoup_->Encrypt(messages));
    *public_key_proto.add_encrypted_y() =
        CamenischShoupCiphertextToProto(y_ciphertext);
  }

  return std::make_tuple(std::move(public_key_proto),
                         std::move(private_key_proto));
}

StatusOr<std::tuple<proto::BbObliviousSignatureRequest,
                    proto::BbObliviousSignatureRequestProof,
                    proto::BbObliviousSignatureRequestPrivateState>>
BbObliviousSignature::GenerateRequestAndProof(
    const std::vector<BigNum>& messages, const std::vector<BigNum>& rs,
    const proto::BbObliviousSignaturePublicKey& public_key,
    const PedersenOverZn::CommitmentAndOpening& commit_and_open_messages,
    const PedersenOverZn::CommitmentAndOpening& commit_and_open_rs) {
  proto::BbObliviousSignatureRequest request_proto;
  proto::BbObliviousSignatureRequestProof proof_proto;
  proto::BbObliviousSignatureRequestPrivateState private_state_proto;

  // Check that sizes are compatible
  if (messages.size() > public_camenisch_shoup_->vector_encryption_length()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignature::GenerateRequest: messages has size ",
        messages.size(),
        " which is larger than vector_encryption_length in parameters_ (",
        public_camenisch_shoup_->vector_encryption_length(), ")"));
  }
  if (rs.size() != messages.size()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignature::GenerateRequest: rs has size ", messages.size(),
        " which is different from messages (", messages.size(), ")"));
  }

  // Generate all "a", "b" and "masked message" values.
  // Each a is a random exponent in the EC group.
  // Each b is a random value of size (2^(security_parameter + challenge_length)
  // * q^2) where lambda is the security parameter, and q is the order of the
  // ec_group in which we compute the BB Oblivious Signature. Each masked
  // message is of the form a*m + b*q, which will be homomorphically added to
  // a*k and ar * y to produce an encryption of a(k+m+yr) + b*q. We also compute
  // alpha = a*m and gamma = a*r which will be needed for the proof.
  std::vector<BigNum> as, bs, alphas, gammas, masked_messages;
  as.reserve(messages.size());
  bs.reserve(messages.size());
  alphas.reserve(messages.size());
  gammas.reserve(messages.size());
  BigNum bs_bound = (ec_group_->GetOrder() * ec_group_->GetOrder())
                        .Lshift(parameters_proto_.challenge_length_bits() +
                                parameters_proto_.security_parameter());
  masked_messages.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    as.push_back(ec_group_->GeneratePrivateKey());
    bs.push_back(ctx_->GenerateRandLessThan(bs_bound));
    alphas.push_back(messages[i] * as.back());
    gammas.push_back(rs[i] * as.back());
    masked_messages.push_back(alphas.back() +
                              (bs.back() * ec_group_->GetOrder()));
  }

  ASSIGN_OR_RETURN(
      CamenischShoupCiphertextWithRand encrypted_masked_messages_and_rand,
      public_camenisch_shoup_->EncryptAndGetRand(masked_messages));

  CamenischShoupCiphertext encrypted_masked_messages =
      std::move(encrypted_masked_messages_and_rand.ct);
  // Used for request proof.
  BigNum encryption_randomness =
      std::move(encrypted_masked_messages_and_rand.r);

  std::vector<CamenischShoupCiphertext> parsed_encrypted_k;
  parsed_encrypted_k.reserve(
      public_camenisch_shoup_->vector_encryption_length());
  std::vector<CamenischShoupCiphertext> parsed_encrypted_y;
  parsed_encrypted_y.reserve(
      public_camenisch_shoup_->vector_encryption_length());

  // Homomorphically add a[i]*k and as[i]*rs[i]*y to the masked_message in the
  // i'th slot, by using the encryption of k in the i'th slot and y in the i'th
  // slot respectively (from the BbObliviousSignature public key).
  for (size_t i = 0; i < messages.size(); ++i) {
    ASSIGN_OR_RETURN(CamenischShoupCiphertext cs_encrypt_k_at_i,
                     public_camenisch_shoup_->ParseCiphertextProto(
                         public_key.encrypted_k(i)));
    encrypted_masked_messages = public_camenisch_shoup_->Add(
        encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(cs_encrypt_k_at_i, as[i]));
    parsed_encrypted_k.push_back(std::move(cs_encrypt_k_at_i));

    ASSIGN_OR_RETURN(CamenischShoupCiphertext cs_encrypt_y_at_i,
                     public_camenisch_shoup_->ParseCiphertextProto(
                         public_key.encrypted_y(i)));
    encrypted_masked_messages = public_camenisch_shoup_->Add(
        encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(cs_encrypt_y_at_i, gammas[i]));
    parsed_encrypted_y.push_back(std::move(cs_encrypt_y_at_i));
  }

  request_proto.set_num_messages(messages.size());
  *request_proto.mutable_encrypted_masked_messages() =
      CamenischShoupCiphertextToProto(encrypted_masked_messages);
  *private_state_proto.mutable_private_as() = BigNumVectorToProto(as);

  // Commit to as, bs.
  // as must be committed separately in order to be able to homomorphically
  // generate batch commitments to alphas and gammas. The i'th commitment
  // contains as[i] in the i'th Pedersen batch-commitment slot, and 0s in all
  // other slots.
  std::vector<BigNum> commit_as, open_as;
  commit_as.reserve(as.size());
  open_as.reserve(as.size());
  for (size_t i = 0; i < as.size(); ++i) {
    std::vector<BigNum> ai_in_ith_position(pedersen_->gs().size(),
                                           ctx_->Zero());
    ai_in_ith_position[i] = as[i];
    ASSIGN_OR_RETURN(PedersenOverZn::CommitmentAndOpening commit_and_open_ai,
                     pedersen_->Commit(ai_in_ith_position));
    commit_as.push_back(std::move(commit_and_open_ai.commitment));
    open_as.push_back(std::move(commit_and_open_ai.opening));
  }

  ASSIGN_OR_RETURN(PedersenOverZn::CommitmentAndOpening commit_and_open_bs,
                   pedersen_->Commit(bs));

  // Homomorphically generate commitment to alphas, gammas. This homomorphically
  // generated commitment will be used in 2 parts of the proof.
  //
  // Taking the example of alphas, recall that alphas[i] = as[i] * messages[i].
  // We want to show that alphas[i] was (1) properly used in computing
  // encrypted_masked_messages, and (2) was properly generated as
  // as[i]*messages[i]. For property (1), we need to show knowledge of alphas[i]
  // and the randomness used to commit to alphas, and for property (2), we need
  // to show that the commitment to alphas was homomorphically generated from
  // Com(as[i]).

  // To support these proofs, we homomorphically generate Com(alpha) as (Prod_i
  // Com(as[i])^messages[i]) * Com(0), where Com(0) is a fresh commitment to 0.
  // Since we generated Com(as[i]) with as[i] each in a different Pedersen
  // vector slot, this will correctly come out to a commitment of alpha, with
  // overall commitment randomness (Sum_i open_as[i] * messages[i]) +
  // open_alphas_2, where open_alphas_2 is the randomness used in the second
  // commitment of 0. We will refer to the overall commitment randomness as
  // open_alphas_1, and the randomness used to commit to 0 as open_alphas_2.
  // These will be used in order to prove properties (1) and (2) respectively.
  //
  // We proceed similarly for gammas, where gammas[i] = as[i] * rs[i].
  std::vector<BigNum> zero_vector(pedersen_->gs().size(), ctx_->Zero());
  ASSIGN_OR_RETURN(
      PedersenOverZn::CommitmentAndOpening temp_commit_and_open_alphas,
      pedersen_->Commit(zero_vector));
  ASSIGN_OR_RETURN(
      PedersenOverZn::CommitmentAndOpening temp_commit_and_open_gammas,
      pedersen_->Commit(zero_vector));

  // commit_alphas and commit_gammas serve as accumulators for the homomorphic
  // computation. open_alphas_1 and open_gammas_1 will serve as accumulators for
  // the randomness in these homomorphically generated commitments.
  // open_alphas_2 and open_gammas_2 will serve to record the randomness used
  // in the commitments to 0.
  PedersenOverZn::Commitment commit_alphas =
      std::move(temp_commit_and_open_alphas.commitment);
  PedersenOverZn::Commitment commit_gammas =
      std::move(temp_commit_and_open_gammas.commitment);
  PedersenOverZn::Opening open_alphas_1 =
      std::move(temp_commit_and_open_alphas.opening);
  PedersenOverZn::Opening open_gammas_1 =
      std::move(temp_commit_and_open_gammas.opening);
  PedersenOverZn::Opening open_alphas_2 = open_alphas_1;
  PedersenOverZn::Opening open_gammas_2 = open_gammas_1;

  for (size_t i = 0; i < messages.size(); ++i) {
    commit_alphas = pedersen_->Add(
        commit_alphas, pedersen_->Multiply(commit_as[i], messages[i]));
    commit_gammas =
        pedersen_->Add(commit_gammas, pedersen_->Multiply(commit_as[i], rs[i]));
    open_alphas_1 = open_alphas_1 + (open_as[i] * messages[i]);
    open_gammas_1 = open_gammas_1 + (open_as[i] * rs[i]);
  }

  // Generate dummy exponents for all values
  BigNum dummy_messages_bound =
      ec_group_->GetOrder().Lshift(parameters_proto_.challenge_length_bits() +
                                   parameters_proto_.security_parameter());
  BigNum dummy_rs_bound = dummy_messages_bound;
  BigNum dummy_as_bound = dummy_messages_bound;
  BigNum dummy_bs_bound =
      bs_bound.Lshift(parameters_proto_.challenge_length_bits() +
                      parameters_proto_.security_parameter());
  BigNum dummy_alphas_bound = dummy_as_bound * ec_group_->GetOrder();
  BigNum dummy_gammas_bound = dummy_alphas_bound;
  BigNum dummy_openings_bound =
      pedersen_->n().Lshift(parameters_proto_.challenge_length_bits() +
                            parameters_proto_.security_parameter());

  // The homomorphically computed openings for Com(alphas) and Com(gammas) need
  // larger dummy values.
  BigNum dummy_homomorphically_computed_openings_bound =
      dummy_openings_bound * ec_group_->GetOrder() *
      ctx_->CreateBigNum(messages.size() + 1);
  BigNum dummy_encryption_randomness_bound =
      public_camenisch_shoup_->n().Lshift(
          parameters_proto_.challenge_length_bits() +
          parameters_proto_.security_parameter());

  std::vector<BigNum> dummy_messages;
  dummy_messages.reserve(messages.size());
  std::vector<BigNum> dummy_rs;
  dummy_rs.reserve(messages.size());
  std::vector<BigNum> dummy_as;
  dummy_as.reserve(messages.size());
  std::vector<BigNum> dummy_as_openings;
  dummy_as_openings.reserve(messages.size());
  std::vector<BigNum> dummy_bs;
  dummy_bs.reserve(messages.size());
  std::vector<BigNum> dummy_alphas;
  dummy_alphas.reserve(messages.size());
  std::vector<BigNum> dummy_gammas;
  dummy_gammas.reserve(messages.size());
  std::vector<BigNum> dummy_masked_messages;
  dummy_masked_messages.reserve(messages.size());

  for (size_t i = 0; i < messages.size(); ++i) {
    dummy_messages.push_back(ctx_->GenerateRandLessThan(dummy_messages_bound));
    dummy_rs.push_back(ctx_->GenerateRandLessThan(dummy_rs_bound));
    dummy_as.push_back(ctx_->GenerateRandLessThan(dummy_as_bound));
    dummy_as_openings.push_back(
        ctx_->GenerateRandLessThan(dummy_openings_bound));
    dummy_bs.push_back(ctx_->GenerateRandLessThan(dummy_bs_bound));
    dummy_alphas.push_back(ctx_->GenerateRandLessThan(dummy_alphas_bound));
    dummy_gammas.push_back(ctx_->GenerateRandLessThan(dummy_gammas_bound));
    dummy_masked_messages.push_back(dummy_alphas.back() +
                                    (dummy_bs.back() * ec_group_->GetOrder()));
  }
  BigNum dummy_messages_opening =
      ctx_->GenerateRandLessThan(dummy_openings_bound);
  BigNum dummy_rs_opening = ctx_->GenerateRandLessThan(dummy_openings_bound);
  BigNum dummy_bs_opening = ctx_->GenerateRandLessThan(dummy_openings_bound);
  BigNum dummy_alphas_opening_1 =
      ctx_->GenerateRandLessThan(dummy_homomorphically_computed_openings_bound);
  BigNum dummy_alphas_opening_2 =
      ctx_->GenerateRandLessThan(dummy_openings_bound);
  BigNum dummy_gammas_opening_1 =
      ctx_->GenerateRandLessThan(dummy_homomorphically_computed_openings_bound);
  BigNum dummy_gammas_opening_2 =
      ctx_->GenerateRandLessThan(dummy_openings_bound);
  BigNum dummy_encryption_randomness =
      ctx_->GenerateRandLessThan(dummy_encryption_randomness_bound);

  // Create dummy composites for all values
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment dummy_commit_messages,
      pedersen_->CommitWithRand(dummy_messages, dummy_messages_opening));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment dummy_commit_rs,
                   pedersen_->CommitWithRand(dummy_rs, dummy_rs_opening));
  std::vector<PedersenOverZn::Commitment> dummy_commit_as;
  for (size_t i = 0; i < messages.size(); ++i) {
    std::vector<BigNum> dummy_as_at_i = zero_vector;
    dummy_as_at_i[i] = dummy_as[i];
    ASSIGN_OR_RETURN(
        PedersenOverZn::Commitment dummy_commit_as_at_i,
        pedersen_->CommitWithRand(dummy_as_at_i, dummy_as_openings[i]));
    dummy_commit_as.push_back(std::move(dummy_commit_as_at_i));
  }
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment dummy_commit_bs,
                   pedersen_->CommitWithRand(dummy_bs, dummy_bs_opening));
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment dummy_commit_alphas_1,
      pedersen_->CommitWithRand(dummy_alphas, dummy_alphas_opening_1));
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment dummy_commit_gammas_1,
      pedersen_->CommitWithRand(dummy_gammas, dummy_gammas_opening_1));

  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment dummy_commit_alphas_2,
      pedersen_->CommitWithRand(zero_vector, dummy_alphas_opening_2));
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment dummy_commit_gammas_2,
      pedersen_->CommitWithRand(zero_vector, dummy_gammas_opening_2));
  for (size_t i = 0; i < messages.size(); ++i) {
    dummy_commit_alphas_2 =
        pedersen_->Add(dummy_commit_alphas_2,
                       pedersen_->Multiply(commit_as[i], dummy_messages[i]));
    dummy_commit_gammas_2 = pedersen_->Add(
        dummy_commit_gammas_2, pedersen_->Multiply(commit_as[i], dummy_rs[i]));
  }

  ASSIGN_OR_RETURN(CamenischShoupCiphertext dummy_encrypted_masked_messages,
                   public_camenisch_shoup_->EncryptWithRand(
                       dummy_masked_messages, dummy_encryption_randomness));

  // Homomorphically add a[i]*k + gammas[i]*y to the masked_message in the i'th
  // slot, by using the encryption of k and y in the i'th slot (from the BB
  // Oblivious Signature public key).
  for (size_t i = 0; i < messages.size(); ++i) {
    dummy_encrypted_masked_messages = public_camenisch_shoup_->Add(
        dummy_encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(parsed_encrypted_k[i], dummy_as[i]));
    dummy_encrypted_masked_messages = public_camenisch_shoup_->Add(
        dummy_encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(parsed_encrypted_y[i],
                                          dummy_gammas[i]));
  }

  // Serialize the statement and first message into protos, and generate the
  // challenge
  proto::BbObliviousSignatureRequestProof::Statement proof_statement;
  *proof_statement.mutable_parameters() = parameters_proto_;
  *proof_statement.mutable_public_key() = public_key;
  proof_statement.set_commit_messages(
      commit_and_open_messages.commitment.ToBytes());
  proof_statement.set_commit_rs(commit_and_open_rs.commitment.ToBytes());
  *proof_statement.mutable_commit_as() = BigNumVectorToProto(commit_as);
  proof_statement.set_commit_bs(commit_and_open_bs.commitment.ToBytes());
  proof_statement.set_commit_alphas(commit_alphas.ToBytes());
  proof_statement.set_commit_gammas(commit_gammas.ToBytes());
  *proof_statement.mutable_request() = request_proto;

  proto::BbObliviousSignatureRequestProof::Message1 proof_message_1;
  proof_message_1.set_dummy_commit_messages(dummy_commit_messages.ToBytes());
  proof_message_1.set_dummy_commit_rs(dummy_commit_rs.ToBytes());
  *proof_message_1.mutable_dummy_commit_as() =
      BigNumVectorToProto(dummy_commit_as);
  proof_message_1.set_dummy_commit_bs(dummy_commit_bs.ToBytes());
  proof_message_1.set_dummy_commit_alphas_1(dummy_commit_alphas_1.ToBytes());
  proof_message_1.set_dummy_commit_alphas_2(dummy_commit_alphas_2.ToBytes());
  proof_message_1.set_dummy_commit_gammas_1(dummy_commit_gammas_1.ToBytes());
  proof_message_1.set_dummy_commit_gammas_2(dummy_commit_gammas_2.ToBytes());
  *proof_message_1.mutable_dummy_encrypted_masked_messages() =
      CamenischShoupCiphertextToProto(dummy_encrypted_masked_messages);

  ASSIGN_OR_RETURN(BigNum challenge, GenerateRequestProofChallenge(
                                         proof_statement, proof_message_1));

  // Create masked dummy openings
  std::vector<BigNum> masked_dummy_messages;
  masked_dummy_messages.reserve(messages.size());
  std::vector<BigNum> masked_dummy_rs;
  masked_dummy_rs.reserve(messages.size());
  std::vector<BigNum> masked_dummy_as;
  masked_dummy_as.reserve(messages.size());
  std::vector<BigNum> masked_dummy_as_openings;
  masked_dummy_as_openings.reserve(messages.size());
  std::vector<BigNum> masked_dummy_bs;
  masked_dummy_bs.reserve(messages.size());
  std::vector<BigNum> masked_dummy_alphas;
  masked_dummy_alphas.reserve(messages.size());
  std::vector<BigNum> masked_dummy_gammas;
  masked_dummy_gammas.reserve(messages.size());

  for (size_t i = 0; i < messages.size(); ++i) {
    masked_dummy_messages.push_back(dummy_messages[i] +
                                    challenge * messages[i]);
    masked_dummy_rs.push_back(dummy_rs[i] + challenge * rs[i]);
    masked_dummy_as.push_back(dummy_as[i] + challenge * as[i]);
    masked_dummy_as_openings.push_back(dummy_as_openings[i] +
                                       challenge * open_as[i]);
    masked_dummy_bs.push_back(dummy_bs[i] + challenge * bs[i]);
    masked_dummy_alphas.push_back(dummy_alphas[i] + challenge * alphas[i]);
    masked_dummy_gammas.push_back(dummy_gammas[i] + challenge * gammas[i]);
  }
  BigNum masked_dummy_messages_opening =
      dummy_messages_opening + challenge * commit_and_open_messages.opening;
  BigNum masked_dummy_rs_opening =
      dummy_rs_opening + challenge * commit_and_open_rs.opening;
  BigNum masked_dummy_bs_opening =
      dummy_bs_opening + challenge * commit_and_open_bs.opening;
  BigNum masked_dummy_alphas_opening_1 =
      dummy_alphas_opening_1 + challenge * open_alphas_1;
  BigNum masked_dummy_alphas_opening_2 =
      dummy_alphas_opening_2 + challenge * open_alphas_2;
  BigNum masked_dummy_gammas_opening_1 =
      dummy_gammas_opening_1 + challenge * open_gammas_1;
  BigNum masked_dummy_gammas_opening_2 =
      dummy_gammas_opening_2 + challenge * open_gammas_2;
  BigNum masked_dummy_encryption_randomness =
      dummy_encryption_randomness + challenge * encryption_randomness;

  // Generate proof proto.

  *proof_proto.mutable_commit_as() = BigNumVectorToProto(commit_as);
  proof_proto.set_commit_bs(commit_and_open_bs.commitment.ToBytes());
  proof_proto.set_commit_alphas(commit_alphas.ToBytes());
  proof_proto.set_commit_gammas(commit_gammas.ToBytes());
  proof_proto.set_challenge(challenge.ToBytes());

  proto::BbObliviousSignatureRequestProof::Message2* proof_proto_message_2 =
      proof_proto.mutable_message_2();
  *proof_proto_message_2->mutable_masked_dummy_messages() =
      BigNumVectorToProto(masked_dummy_messages);
  proof_proto_message_2->set_masked_dummy_messages_opening(
      masked_dummy_messages_opening.ToBytes());
  *proof_proto_message_2->mutable_masked_dummy_rs() =
      BigNumVectorToProto(masked_dummy_rs);
  proof_proto_message_2->set_masked_dummy_rs_opening(
      masked_dummy_rs_opening.ToBytes());
  *proof_proto_message_2->mutable_masked_dummy_as() =
      BigNumVectorToProto(masked_dummy_as);
  *proof_proto_message_2->mutable_masked_dummy_as_opening() =
      BigNumVectorToProto(masked_dummy_as_openings);
  *proof_proto_message_2->mutable_masked_dummy_bs() =
      BigNumVectorToProto(masked_dummy_bs);
  proof_proto_message_2->set_masked_dummy_bs_opening(
      masked_dummy_bs_opening.ToBytes());
  *proof_proto_message_2->mutable_masked_dummy_alphas() =
      BigNumVectorToProto(masked_dummy_alphas);
  proof_proto_message_2->set_masked_dummy_alphas_opening_1(
      masked_dummy_alphas_opening_1.ToBytes());
  proof_proto_message_2->set_masked_dummy_alphas_opening_2(
      masked_dummy_alphas_opening_2.ToBytes());
  *proof_proto_message_2->mutable_masked_dummy_gammas() =
      BigNumVectorToProto(masked_dummy_gammas);
  proof_proto_message_2->set_masked_dummy_gammas_opening_1(
      masked_dummy_gammas_opening_1.ToBytes());
  proof_proto_message_2->set_masked_dummy_gammas_opening_2(
      masked_dummy_gammas_opening_2.ToBytes());
  proof_proto_message_2->set_masked_dummy_encryption_randomness(
      masked_dummy_encryption_randomness.ToBytes());

  return std::make_tuple(std::move(request_proto), std::move(proof_proto),
                         std::move(private_state_proto));
}

// Verifies a signature request and proof.
Status BbObliviousSignature::VerifyRequest(
    const proto::BbObliviousSignaturePublicKey& public_key,
    const proto::BbObliviousSignatureRequest& request,
    const proto::BbObliviousSignatureRequestProof& request_proof,
    const PedersenOverZn::Commitment& commit_messages,
    const PedersenOverZn::Commitment& commit_rs) {
  // Create the proof statement
  proto::BbObliviousSignatureRequestProof::Statement proof_statement;
  *proof_statement.mutable_parameters() = parameters_proto_;
  *proof_statement.mutable_public_key() = public_key;
  proof_statement.set_commit_messages(commit_messages.ToBytes());
  proof_statement.set_commit_rs(commit_rs.ToBytes());
  *proof_statement.mutable_commit_as() = request_proof.commit_as();
  proof_statement.set_commit_bs(request_proof.commit_bs());
  proof_statement.set_commit_alphas(request_proof.commit_alphas());
  proof_statement.set_commit_gammas(request_proof.commit_gammas());
  *proof_statement.mutable_request() = request;

  // Parse the components needed for the proof.
  std::vector<PedersenOverZn::Commitment> commit_as =
      ParseBigNumVectorProto(ctx_, request_proof.commit_as());
  PedersenOverZn::Commitment commit_bs =
      ctx_->CreateBigNum(request_proof.commit_bs());
  PedersenOverZn::Commitment commit_alphas =
      ctx_->CreateBigNum(request_proof.commit_alphas());
  PedersenOverZn::Commitment commit_gammas =
      ctx_->CreateBigNum(request_proof.commit_gammas());
  ASSIGN_OR_RETURN(CamenischShoupCiphertext encrypted_masked_messages,
                   public_camenisch_shoup_->ParseCiphertextProto(
                       request.encrypted_masked_messages()));

  // Parse challenge from the proof.
  BigNum challenge_from_proof = ctx_->CreateBigNum(request_proof.challenge());

  // Parse the masked dummy values from the proof.
  std::vector<BigNum> masked_dummy_messages = ParseBigNumVectorProto(
      ctx_, request_proof.message_2().masked_dummy_messages());
  BigNum masked_dummy_messages_opening = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_messages_opening());
  std::vector<BigNum> masked_dummy_rs =
      ParseBigNumVectorProto(ctx_, request_proof.message_2().masked_dummy_rs());
  BigNum masked_dummy_rs_opening =
      ctx_->CreateBigNum(request_proof.message_2().masked_dummy_rs_opening());
  std::vector<BigNum> masked_dummy_as =
      ParseBigNumVectorProto(ctx_, request_proof.message_2().masked_dummy_as());
  std::vector<BigNum> masked_dummy_as_opening = ParseBigNumVectorProto(
      ctx_, request_proof.message_2().masked_dummy_as_opening());
  std::vector<BigNum> masked_dummy_bs =
      ParseBigNumVectorProto(ctx_, request_proof.message_2().masked_dummy_bs());
  BigNum masked_dummy_bs_opening =
      ctx_->CreateBigNum(request_proof.message_2().masked_dummy_bs_opening());
  std::vector<BigNum> masked_dummy_alphas = ParseBigNumVectorProto(
      ctx_, request_proof.message_2().masked_dummy_alphas());
  BigNum masked_dummy_alphas_opening_1 = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_alphas_opening_1());
  BigNum masked_dummy_alphas_opening_2 = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_alphas_opening_2());
  std::vector<BigNum> masked_dummy_gammas = ParseBigNumVectorProto(
      ctx_, request_proof.message_2().masked_dummy_gammas());
  BigNum masked_dummy_gammas_opening_1 = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_gammas_opening_1());
  BigNum masked_dummy_gammas_opening_2 = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_gammas_opening_2());
  BigNum masked_dummy_encryption_randomness = ctx_->CreateBigNum(
      request_proof.message_2().masked_dummy_encryption_randomness());

  if (request.num_messages() >
      public_camenisch_shoup_->vector_encryption_length()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignature::VerifyRequest: messages has size ",
        request.num_messages(),
        " which is larger than vector_encryption_length in parameters (",
        public_camenisch_shoup_->vector_encryption_length(), ")"));
  }

  // Check that all vectors have the correct size.
  if (commit_as.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of commit_as: expected ",
        request.num_messages(), ", actual ", commit_as.size()));
  }
  if (masked_dummy_messages.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_messages: expected ",
        request.num_messages(), ", actual ", masked_dummy_messages.size()));
  }
  if (masked_dummy_rs.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_rs: expected ",
        request.num_messages(), ", actual ", masked_dummy_rs.size()));
  }
  if (masked_dummy_as.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_as: expected ",
        request.num_messages(), ", actual ", masked_dummy_as.size()));
  }
  if (masked_dummy_bs.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_bs: expected ",
        request.num_messages(), ", actual ", masked_dummy_bs.size()));
  }
  if (masked_dummy_alphas.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_alphas: expected ",
        request.num_messages(), ", actual ", masked_dummy_alphas.size()));
  }
  if (masked_dummy_gammas.size() != request.num_messages()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "BbObliviousSignatures::VerifyRequest: request proof has wrong number "
        "of masked_dummy_gammas: expected ",
        request.num_messages(), ", actual ", masked_dummy_gammas.size()));
  }

  // Verify bounds.
  BigNum masked_dummy_messages_bound =
      ec_group_->GetOrder().Lshift(parameters_proto_.challenge_length_bits() +
                                   parameters_proto_.security_parameter() + 1);
  BigNum masked_dummy_rs_bound = masked_dummy_messages_bound;
  BigNum masked_dummy_as_bound = masked_dummy_messages_bound;
  BigNum masked_dummy_bs_bound =
      (ec_group_->GetOrder() * ec_group_->GetOrder())
          .Lshift(2 * parameters_proto_.challenge_length_bits() +
                  2 * parameters_proto_.security_parameter() + 1);
  BigNum masked_dummy_alphas_bound =
      masked_dummy_as_bound * ec_group_->GetOrder();
  BigNum masked_dummy_gammas_bound = masked_dummy_alphas_bound;

  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    if (masked_dummy_messages[i] >= masked_dummy_messages_bound) {
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignatures::VerifyRequest: The ", i,
          "th entry of masked_dummy_messages,",
          masked_dummy_messages[i].ToDecimalString(), " (bit length ",
          masked_dummy_messages[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_messages_bound.ToDecimalString(), " (bit length ",
          masked_dummy_messages_bound.BitLength(), ")"));
    }
    if (masked_dummy_as[i] >= masked_dummy_as_bound) {
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignatures::VerifyRequest: The ", i,
          "th entry of masked_dummy_as,", masked_dummy_as[i].ToDecimalString(),
          " (bit length ", masked_dummy_as[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_as_bound.ToDecimalString(), " (bit length ",
          masked_dummy_as_bound.BitLength(), ")"));
    }
    if (masked_dummy_bs[i] >= masked_dummy_bs_bound) {
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignatures::VerifyRequest: The ", i,
          "th entry of masked_dummy_bs,", masked_dummy_bs[i].ToDecimalString(),
          " (bit length ", masked_dummy_bs[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_bs_bound.ToDecimalString(), " (bit length ",
          masked_dummy_bs_bound.BitLength(), ")"));
    }
    if (masked_dummy_alphas[i] >= masked_dummy_alphas_bound) {
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignatures::VerifyRequest: The ", i,
          "th entry of masked_dummy_alphas,",
          masked_dummy_alphas[i].ToDecimalString(), " (bit length ",
          masked_dummy_alphas[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_alphas_bound.ToDecimalString(), " (bit length ",
          masked_dummy_alphas_bound.BitLength(), ")"));
    }
    if (masked_dummy_gammas[i] >= masked_dummy_gammas_bound) {
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignatures::VerifyRequest: The ", i,
          "th entry of masked_dummy_gammas,",
          masked_dummy_gammas[i].ToDecimalString(), " (bit length ",
          masked_dummy_gammas[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_gammas_bound.ToDecimalString(), " (bit length ",
          masked_dummy_gammas_bound.BitLength(), ")"));
    }
  }

  // Create masked dummy composite values

  ASSIGN_OR_RETURN(PedersenOverZn::Commitment masked_dummy_commit_messages,
                   pedersen_->CommitWithRand(masked_dummy_messages,
                                             masked_dummy_messages_opening));
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commit_rs,
      pedersen_->CommitWithRand(masked_dummy_rs, masked_dummy_rs_opening));

  std::vector<PedersenOverZn::Commitment> masked_dummy_commit_as;
  masked_dummy_commit_as.reserve(commit_as.size());
  std::vector<BigNum> zero_vector(pedersen_->gs().size(), ctx_->Zero());
  for (size_t i = 0; i < commit_as.size(); ++i) {
    std::vector<BigNum> masked_dummy_ai_at_i = zero_vector;
    masked_dummy_ai_at_i[i] = masked_dummy_as[i];
    ASSIGN_OR_RETURN(PedersenOverZn::Commitment masked_dummy_commit_ai,
                     pedersen_->CommitWithRand(masked_dummy_ai_at_i,
                                               masked_dummy_as_opening[i]));
    masked_dummy_commit_as.push_back(masked_dummy_commit_ai);
  }
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commit_bs,
      pedersen_->CommitWithRand(masked_dummy_bs, masked_dummy_bs_opening));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment masked_dummy_commit_alphas_1,
                   pedersen_->CommitWithRand(masked_dummy_alphas,
                                             masked_dummy_alphas_opening_1));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment masked_dummy_commit_gammas_1,
                   pedersen_->CommitWithRand(masked_dummy_gammas,
                                             masked_dummy_gammas_opening_1));

  // masked_dummy_alphas_2 and masked_dummy_gammas_2 are homomorphically
  // computed from commit_as.
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commit_alphas_2,
      pedersen_->CommitWithRand(zero_vector, masked_dummy_alphas_opening_2));
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commit_gammas_2,
      pedersen_->CommitWithRand(zero_vector, masked_dummy_gammas_opening_2));
  for (size_t i = 0; i < commit_as.size(); ++i) {
    masked_dummy_commit_alphas_2 = pedersen_->Add(
        pedersen_->Multiply(commit_as[i], masked_dummy_messages[i]),
        masked_dummy_commit_alphas_2);
    masked_dummy_commit_gammas_2 =
        pedersen_->Add(pedersen_->Multiply(commit_as[i], masked_dummy_rs[i]),
                       masked_dummy_commit_gammas_2);
  }

  // Compute the masked_dummy_encrypted_masked_messages homomorphically.
  std::vector<BigNum> dummy_masked_encrypted_masked_messages;
  dummy_masked_encrypted_masked_messages.reserve(masked_dummy_messages.size());
  for (size_t i = 0; i < masked_dummy_messages.size(); ++i) {
    dummy_masked_encrypted_masked_messages.push_back(
        masked_dummy_alphas[i] + masked_dummy_bs[i] * ec_group_->GetOrder());
  }

  ASSIGN_OR_RETURN(
      CamenischShoupCiphertext masked_dummy_encrypted_masked_messages,
      public_camenisch_shoup_->EncryptWithRand(
          dummy_masked_encrypted_masked_messages,
          masked_dummy_encryption_randomness));

  // Homomorphically add a[i]*k and as[i]*rs[i]*y to the masked_message in the
  // i'th slot, by using the encryption of k in the i'th slot and y in the i'th
  // slot respectively (from the BbObliviousSignature public key).
  for (size_t i = 0; i < dummy_masked_encrypted_masked_messages.size(); ++i) {
    ASSIGN_OR_RETURN(CamenischShoupCiphertext cs_encrypt_k_at_i,
                     public_camenisch_shoup_->ParseCiphertextProto(
                         public_key.encrypted_k(i)));
    masked_dummy_encrypted_masked_messages = public_camenisch_shoup_->Add(
        masked_dummy_encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(cs_encrypt_k_at_i,
                                          masked_dummy_as[i]));

    ASSIGN_OR_RETURN(CamenischShoupCiphertext cs_encrypt_y_at_i,
                     public_camenisch_shoup_->ParseCiphertextProto(
                         public_key.encrypted_y(i)));
    masked_dummy_encrypted_masked_messages = public_camenisch_shoup_->Add(
        masked_dummy_encrypted_masked_messages,
        public_camenisch_shoup_->Multiply(cs_encrypt_y_at_i,
                                          masked_dummy_gammas[i]));
  }

  //  Recreate dummy composites from masked dummy composites (in order to
  //  regenerate Proof Message 1). Each dummy_composite is computed as
  //  masked_dummy_composite / original_value^challenge_in_proof.

  ASSIGN_OR_RETURN(BigNum commit_messages_to_challenge_inverse,
                   pedersen_->Multiply(commit_messages, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_messages = pedersen_->Add(
      masked_dummy_commit_messages, commit_messages_to_challenge_inverse);

  ASSIGN_OR_RETURN(BigNum commit_rs_to_challenge_inverse,
                   pedersen_->Multiply(commit_rs, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_rs =
      pedersen_->Add(masked_dummy_commit_rs, commit_rs_to_challenge_inverse);

  std::vector<PedersenOverZn::Commitment> dummy_commit_as;
  dummy_commit_as.reserve(commit_as.size());
  for (size_t i = 0; i < commit_as.size(); ++i) {
    ASSIGN_OR_RETURN(BigNum commit_as_to_challenge_inverse,
                     pedersen_->Multiply(commit_as[i], challenge_from_proof)
                         .ModInverse(pedersen_->n()));
    dummy_commit_as.push_back(pedersen_->Add(masked_dummy_commit_as[i],
                                             commit_as_to_challenge_inverse));
  }

  ASSIGN_OR_RETURN(BigNum commit_bs_to_challenge_inverse,
                   pedersen_->Multiply(commit_bs, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_bs =
      pedersen_->Add(masked_dummy_commit_bs, commit_bs_to_challenge_inverse);

  ASSIGN_OR_RETURN(BigNum commit_alphas_to_challenge_inverse,
                   pedersen_->Multiply(commit_alphas, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_alphas_1 = pedersen_->Add(
      masked_dummy_commit_alphas_1, commit_alphas_to_challenge_inverse);
  PedersenOverZn::Commitment dummy_commit_alphas_2 = pedersen_->Add(
      masked_dummy_commit_alphas_2, commit_alphas_to_challenge_inverse);

  ASSIGN_OR_RETURN(BigNum commit_gammas_to_challenge_inverse,
                   pedersen_->Multiply(commit_gammas, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_gammas_1 = pedersen_->Add(
      masked_dummy_commit_gammas_1, commit_gammas_to_challenge_inverse);
  PedersenOverZn::Commitment dummy_commit_gammas_2 = pedersen_->Add(
      masked_dummy_commit_gammas_2, commit_gammas_to_challenge_inverse);

  // Some extra work is needed for the Camenisch Shoup ciphertext since it
  // doesn't natively support inverse.
  CamenischShoupCiphertext encrypted_masked_messages_to_challenge =
      public_camenisch_shoup_->Multiply(encrypted_masked_messages,
                                        challenge_from_proof);
  ASSIGN_OR_RETURN(BigNum encrypted_masked_messages_to_challenge_u_inverse,
                   encrypted_masked_messages_to_challenge.u.ModInverse(
                       public_camenisch_shoup_->modulus()));
  std::vector<BigNum> encrypted_masked_messages_to_challenge_es_inverse;
  encrypted_masked_messages_to_challenge_es_inverse.reserve(
      encrypted_masked_messages_to_challenge.es.size());
  for (size_t i = 0; i < encrypted_masked_messages_to_challenge.es.size();
       ++i) {
    ASSIGN_OR_RETURN(BigNum encrypted_masked_messages_to_challenge_e_inverse,
                     encrypted_masked_messages_to_challenge.es[i].ModInverse(
                         public_camenisch_shoup_->modulus()));
    encrypted_masked_messages_to_challenge_es_inverse.push_back(
        std::move(encrypted_masked_messages_to_challenge_e_inverse));
  }
  CamenischShoupCiphertext encrypted_masked_messages_to_challenge_inverse{
      std::move(encrypted_masked_messages_to_challenge_u_inverse),
      std::move(encrypted_masked_messages_to_challenge_es_inverse)};
  CamenischShoupCiphertext dummy_encrypted_masked_messages =
      public_camenisch_shoup_->Add(
          masked_dummy_encrypted_masked_messages,
          encrypted_masked_messages_to_challenge_inverse);

  // Package dummy_composites into Proof message_1.
  proto::BbObliviousSignatureRequestProof::Message1 message_1;
  message_1.set_dummy_commit_messages(dummy_commit_messages.ToBytes());
  message_1.set_dummy_commit_rs(dummy_commit_rs.ToBytes());
  *message_1.mutable_dummy_commit_as() = BigNumVectorToProto(dummy_commit_as);
  message_1.set_dummy_commit_bs(dummy_commit_bs.ToBytes());
  message_1.set_dummy_commit_alphas_1(dummy_commit_alphas_1.ToBytes());
  message_1.set_dummy_commit_alphas_2(dummy_commit_alphas_2.ToBytes());
  message_1.set_dummy_commit_gammas_1(dummy_commit_gammas_1.ToBytes());
  message_1.set_dummy_commit_gammas_2(dummy_commit_gammas_2.ToBytes());
  *message_1.mutable_dummy_encrypted_masked_messages() =
      CamenischShoupCiphertextToProto(dummy_encrypted_masked_messages);

  // Reconstruct the challenge and check that it matches the one supplied in the
  // proof.
  ASSIGN_OR_RETURN(BigNum reconstructed_challenge,
                   GenerateRequestProofChallenge(proof_statement, message_1));

  if (reconstructed_challenge != challenge_from_proof) {
    return absl::InvalidArgumentError(
        absl::StrCat("BbObliviousSignature::VerifyRequest: Failed to verify "
                     "request proof. Challenge in proof (",
                     challenge_from_proof.ToDecimalString(),
                     ") does not match reconstructed challenge (",
                     reconstructed_challenge.ToDecimalString(), ")."));
  }

  return absl::OkStatus();
}

StatusOr<std::tuple<proto::BbObliviousSignatureResponse,
                    proto::BbObliviousSignatureResponseProof>>
BbObliviousSignature::GenerateResponseAndProof(
    const proto::BbObliviousSignatureRequest& request,
    const proto::BbObliviousSignaturePublicKey& public_key,
    const proto::BbObliviousSignaturePrivateKey& private_key,
    const PedersenOverZn::Commitment& commit_messages,
    const PedersenOverZn::Commitment& commit_rs,
    PrivateCamenischShoup* private_camenisch_shoup) {
  proto::BbObliviousSignatureResponse response_proto;
  proto::BbObliviousSignatureResponseProof response_proof_proto;

  if (request.num_messages() >
          public_camenisch_shoup_->vector_encryption_length() ||
      request.num_messages() < 0) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::GenerateResponse: invalid num_messages in "
        "request.");
  }

  // We will refer to the values decrypted from the CS ciphertexts as betas.
  // These betas are implicitly bounded as long as the request proof was
  // verified (and the sender generated its parameters correctly).
  ASSIGN_OR_RETURN(CamenischShoupCiphertext encrypted_masked_messages,
                   public_camenisch_shoup_->ParseCiphertextProto(
                       request.encrypted_masked_messages()));
  ASSIGN_OR_RETURN(std::vector<BigNum> betas,
                   private_camenisch_shoup->Decrypt(encrypted_masked_messages));

  // Truncate the last few elements of betas, if it's larger than num_messages.
  // (These should be all zeros.)
  betas.erase(betas.begin() + request.num_messages(), betas.end());

  std::vector<ECPoint> masked_prf_values;
  masked_prf_values.reserve(request.num_messages());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    ASSIGN_OR_RETURN(BigNum beta_inverse,
                     betas[i].ModInverse(ec_group_->GetOrder()));
    ASSIGN_OR_RETURN(ECPoint masked_prf_value, base_g_.Mul(beta_inverse));
    masked_prf_values.push_back(std::move(masked_prf_value));
  }

  ASSIGN_OR_RETURN(*response_proto.mutable_masked_signature_values(),
                   ECPointVectorToProto(masked_prf_values));

  // Commit to decrypted_values (aka betas)
  ASSIGN_OR_RETURN(auto commit_and_open_betas, pedersen_->Commit(betas));
  response_proof_proto.set_commit_betas(
      commit_and_open_betas.commitment.ToBytes());

  // (1) Generate Proof Message 1

  // (1.1) Create dummy_betas, dummy_xs and dummy commitment-opening.
  // beta is bounded by 2^(challenge_length + security+parameter) * q^3, so
  // dummy_beta is bounded by the beta bound plus an additional
  // 2^(challenge_length + security_parameter).
  BigNum dummy_betas_bound =
      ctx_->One()
          .Lshift(2 * parameters_proto_.challenge_length_bits() +
                  2 * parameters_proto_.security_parameter())
          .Mul(ec_group_->GetOrder())
          .Mul(ec_group_->GetOrder())
          .Mul(ec_group_->GetOrder());
  std::vector<BigNum> dummy_betas;
  dummy_betas.reserve(request.num_messages());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    dummy_betas.push_back(ctx_->GenerateRandLessThan(dummy_betas_bound));
  }

  std::vector<BigNum> dummy_xs;
  dummy_xs.reserve(public_camenisch_shoup_->vector_encryption_length());
  BigNum dummy_xs_bound = public_camenisch_shoup_->n().Lshift(
      parameters_proto_.challenge_length_bits() +
      parameters_proto_.security_parameter());
  for (uint64_t i = 0; i < public_camenisch_shoup_->vector_encryption_length();
       ++i) {
    dummy_xs.push_back(ctx_->GenerateRandLessThan(dummy_xs_bound));
  }

  // Dummy opening has the same size as dummy_xs.
  BigNum dummy_beta_opening = ctx_->GenerateRandLessThan(dummy_xs_bound);
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment dummy_commit_betas,
                   pedersen_->CommitWithRand(dummy_betas, dummy_beta_opening));

  // (1.2) Use the dummy values above to create dummy_cs_ys, dummy_commit_betas,
  // dummy_enc_mask_messages_es and dummy_base_gs.
  std::vector<BigNum> dummy_cs_ys;
  dummy_cs_ys.reserve(public_camenisch_shoup_->vector_encryption_length());
  for (uint64_t i = 0; i < public_camenisch_shoup_->vector_encryption_length();
       ++i) {
    dummy_cs_ys.push_back(private_camenisch_shoup->g().ModExp(
        dummy_xs[i], private_camenisch_shoup->modulus()));
  }

  // intermediate_es contains (1+n)^dummy_betas[i] mod n^(s+1) in the "es"
  // component. This is achieved by encrypting dummy_betas with randomness 0.
  ASSIGN_OR_RETURN(
      CamenischShoupCiphertext intermediate_ciphertext,
      private_camenisch_shoup->EncryptWithRand(dummy_betas, ctx_->Zero()));
  // dummy_enc_mask_messages_es contains u^dummy_xs[i] * (1+n)^dummy_betas[i]
  // mod n^(s+1) in the "es" component.
  std::vector<BigNum> dummy_enc_mask_messages_es;
  dummy_enc_mask_messages_es.reserve(
      public_camenisch_shoup_->vector_encryption_length());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    BigNum dummy_e =
        encrypted_masked_messages.u
            .ModExp(dummy_xs[i], private_camenisch_shoup->modulus())
            .ModMul(intermediate_ciphertext.es[i],
                    private_camenisch_shoup->modulus());
    dummy_enc_mask_messages_es.push_back(std::move(dummy_e));
  }

  std::vector<ECPoint> dummy_base_gs;
  dummy_base_gs.reserve(request.num_messages());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    ASSIGN_OR_RETURN(ECPoint dummy_base_g,
                     masked_prf_values[i].Mul(dummy_betas[i]));
    dummy_base_gs.push_back(std::move(dummy_base_g));
  }

  proto::BbObliviousSignatureResponseProof::Message1 proof_message_1;
  *proof_message_1.mutable_dummy_camenisch_shoup_ys() =
      BigNumVectorToProto(dummy_cs_ys);
  proof_message_1.set_dummy_commit_betas(dummy_commit_betas.ToBytes());
  *proof_message_1.mutable_dummy_encrypted_masked_messages_es() =
      BigNumVectorToProto(dummy_enc_mask_messages_es);
  ASSIGN_OR_RETURN(*proof_message_1.mutable_dummy_base_gs(),
                   ECPointVectorToProto(dummy_base_gs));

  // (2) Generate challenge
  ASSIGN_OR_RETURN(
      BigNum challenge,
      GenerateResponseProofChallenge(
          public_key, commit_messages, commit_rs, request, response_proto,
          commit_and_open_betas.commitment, proof_message_1));
  response_proof_proto.set_challenge(challenge.ToBytes());

  // (3) Generate Message 2
  // Compute all masked dummy values: masked_dummy_betas,
  // masked_dummy_xs, masked_dummy_beta_opening
  std::vector<BigNum> masked_dummy_betas;
  masked_dummy_betas.reserve(request.num_messages());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    masked_dummy_betas.push_back(dummy_betas[i] + betas[i].Mul(challenge));
  }
  std::vector<BigNum> masked_dummy_xs;
  masked_dummy_xs.reserve(public_camenisch_shoup_->vector_encryption_length());
  for (uint64_t i = 0; i < public_camenisch_shoup_->vector_encryption_length();
       ++i) {
    masked_dummy_xs.push_back(
        dummy_xs[i] + (private_camenisch_shoup->xs()[i].Mul(challenge)));
  }
  BigNum masked_dummy_beta_opening =
      dummy_beta_opening + commit_and_open_betas.opening.Mul(challenge);

  proto::BbObliviousSignatureResponseProof::Message2* response_proof_message_2 =
      response_proof_proto.mutable_message_2();
  *response_proof_message_2->mutable_masked_dummy_betas() =
      BigNumVectorToProto(masked_dummy_betas);
  *response_proof_message_2->mutable_masked_dummy_camenisch_shoup_xs() =
      BigNumVectorToProto(masked_dummy_xs);
  response_proof_message_2->set_masked_dummy_beta_opening(
      masked_dummy_beta_opening.ToBytes());

  return std::make_tuple(response_proto, response_proof_proto);
}

Status BbObliviousSignature::VerifyResponse(
    const proto::BbObliviousSignaturePublicKey& public_key,
    const proto::BbObliviousSignatureResponse& response,
    const proto::BbObliviousSignatureResponseProof& response_proof,
    const proto::BbObliviousSignatureRequest& request,
    const PedersenOverZn::Commitment& commit_messages,
    const PedersenOverZn::Commitment& commit_rs) {
  if (response.masked_signature_values().serialized_ec_points_size() !=
      request.num_messages()) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::VerifyResponse: response has a different number "
        "of masked_signature_values values than the request");
  }

  if (response_proof.message_2()
          .masked_dummy_camenisch_shoup_xs()
          .serialized_big_nums_size() !=
      public_camenisch_shoup_->vector_encryption_length()) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::VerifyResponse: response proof has wrong number "
        "of masked_dummy_camenisch_shoup_xs in message 2.");
  }
  if (response_proof.message_2()
          .masked_dummy_betas()
          .serialized_big_nums_size() != request.num_messages()) {
    return absl::InvalidArgumentError(
        "BbObliviousSignature::VerifyResponse: response proof has wrong number "
        "of masked_dummy_betas in message 2.");
  }

  // Parse the needed request, response and response proof elements.
  ASSIGN_OR_RETURN(CamenischShoupCiphertext encrypted_masked_messages,
                   public_camenisch_shoup_->ParseCiphertextProto(
                       request.encrypted_masked_messages()));
  ASSIGN_OR_RETURN(std::vector<ECPoint> masked_signature_values,
                   ParseECPointVectorProto(ctx_, ec_group_,
                                           response.masked_signature_values()));
  PedersenOverZn::Commitment commit_betas =
      ctx_->CreateBigNum(response_proof.commit_betas());
  BigNum challenge_from_proof = ctx_->CreateBigNum(response_proof.challenge());
  std::vector<BigNum> masked_dummy_camenisch_shoup_xs = ParseBigNumVectorProto(
      ctx_, response_proof.message_2().masked_dummy_camenisch_shoup_xs());
  std::vector<BigNum> masked_dummy_betas = ParseBigNumVectorProto(
      ctx_, response_proof.message_2().masked_dummy_betas());
  BigNum masked_dummy_beta_opening = ctx_->CreateBigNum(
      response_proof.message_2().masked_dummy_beta_opening());

  // Check the lengths of masked dummy betas
  BigNum masked_dummy_betas_bound =
      ctx_->One().Lshift(2 * parameters_proto_.challenge_length_bits() +
                         2 * parameters_proto_.security_parameter() + 1) *
      ec_group_->GetOrder() * ec_group_->GetOrder() * ec_group_->GetOrder();
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    if (masked_dummy_betas[i] >= masked_dummy_betas_bound)
      return absl::InvalidArgumentError(absl::StrCat(
          "BbObliviousSignature::VerifyResponse: The ", i,
          "th entry of masked_dummy_betas,",
          masked_dummy_betas[i].ToDecimalString(), " (bit length ",
          masked_dummy_betas[i].BitLength(), ")",
          ",is larger than the acceptable bound: ",
          masked_dummy_betas_bound.ToDecimalString(), " (bit length ",
          masked_dummy_betas_bound.BitLength(), ")"));
  }

  // Reconstruct each element of Proof message 1.
  proto::BbObliviousSignatureResponseProof::Message1 reconstructed_message_1;

  // Reconstruct dummy_base_gs.
  std::vector<ECPoint> dummy_base_gs;
  dummy_base_gs.reserve(request.num_messages());
  ASSIGN_OR_RETURN(ECPoint base_g_to_challenge,
                   base_g_.Mul(challenge_from_proof));
  ASSIGN_OR_RETURN(ECPoint base_g_to_challenge_inverse,
                   base_g_to_challenge.Inverse());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    ASSIGN_OR_RETURN(ECPoint masked_dummy_g,
                     masked_signature_values[i].Mul(masked_dummy_betas[i]));
    // Compute dummy_base_g as masked_dummy_g / g^c
    ASSIGN_OR_RETURN(ECPoint dummy_base_g,
                     masked_dummy_g.Add(base_g_to_challenge_inverse));
    dummy_base_gs.push_back(std::move(dummy_base_g));
  }

  ASSIGN_OR_RETURN(*reconstructed_message_1.mutable_dummy_base_gs(),
                   ECPointVectorToProto(dummy_base_gs));

  // Reconstruct dummy_es
  // es[i] of intermediate_ciphertext is (1+n)^masked_dummy_betas[i].
  ASSIGN_OR_RETURN(CamenischShoupCiphertext intermediate_ciphertext,
                   public_camenisch_shoup_->EncryptWithRand(masked_dummy_betas,
                                                            ctx_->Zero()));
  std::vector<BigNum> dummy_es;
  dummy_es.reserve(request.num_messages());
  for (uint64_t i = 0; i < request.num_messages(); ++i) {
    // masked_dummy_e = (1+n)^masked_dummy_betas[i] * u^masked_dummy_xs[i]
    BigNum masked_dummy_e = intermediate_ciphertext.es[i].ModMul(
        encrypted_masked_messages.u.ModExp(masked_dummy_camenisch_shoup_xs[i],
                                           public_camenisch_shoup_->modulus()),
        public_camenisch_shoup_->modulus());

    ASSIGN_OR_RETURN(
        BigNum e_to_challenge_inverse,
        encrypted_masked_messages.es[i]
            .ModExp(challenge_from_proof, public_camenisch_shoup_->modulus())
            .ModInverse(public_camenisch_shoup_->modulus()));

    BigNum dummy_e = masked_dummy_e.ModMul(e_to_challenge_inverse,
                                           public_camenisch_shoup_->modulus());
    dummy_es.push_back(std::move(dummy_e));
  }
  *reconstructed_message_1.mutable_dummy_encrypted_masked_messages_es() =
      BigNumVectorToProto(dummy_es);

  // Reconstruct dummy_commit_betas.
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commit_betas,
      pedersen_->CommitWithRand(masked_dummy_betas, masked_dummy_beta_opening));
  ASSIGN_OR_RETURN(BigNum commit_betas_to_challenge_inverse,
                   pedersen_->Multiply(commit_betas, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_betas = pedersen_->Add(
      masked_dummy_commit_betas, commit_betas_to_challenge_inverse);
  reconstructed_message_1.set_dummy_commit_betas(dummy_commit_betas.ToBytes());

  // Reconstruct dummy_camenisch_shoup_ys
  std::vector<BigNum> dummy_camenisch_shoup_ys;
  dummy_camenisch_shoup_ys.reserve(
      public_camenisch_shoup_->vector_encryption_length());
  for (uint64_t i = 0; i < public_camenisch_shoup_->vector_encryption_length();
       ++i) {
    BigNum masked_dummy_y = public_camenisch_shoup_->g().ModExp(
        masked_dummy_camenisch_shoup_xs[i], public_camenisch_shoup_->modulus());
    ASSIGN_OR_RETURN(
        BigNum y_to_challenge_inverse,
        public_camenisch_shoup_->ys()[i]
            .ModExp(challenge_from_proof, public_camenisch_shoup_->modulus())
            .ModInverse(public_camenisch_shoup_->modulus()));
    BigNum dummy_camenisch_shoup_y = masked_dummy_y.ModMul(
        y_to_challenge_inverse, public_camenisch_shoup_->modulus());
    dummy_camenisch_shoup_ys.push_back(std::move(dummy_camenisch_shoup_y));
  }
  *reconstructed_message_1.mutable_dummy_camenisch_shoup_ys() =
      BigNumVectorToProto(dummy_camenisch_shoup_ys);

  // Reconstruct the challenge by applying FiatShamir to the reconstructed first
  // message, and ensure it exactly matches the challenge in the proof.
  ASSIGN_OR_RETURN(BigNum reconstructed_challenge,
                   GenerateResponseProofChallenge(
                       public_key, commit_messages, commit_rs, request,
                       response, commit_betas, reconstructed_message_1));

  if (reconstructed_challenge != challenge_from_proof) {
    return absl::InvalidArgumentError(
        absl::StrCat("BbObliviousSignature::VerifyResponse: Failed to verify "
                     "response proof. Challenge in proof (",
                     challenge_from_proof.ToDecimalString(),
                     ") does not match reconstructed challenge (",
                     reconstructed_challenge.ToDecimalString(), ")."));
  }
  return absl::OkStatus();
}

StatusOr<std::vector<ECPoint>> BbObliviousSignature::ExtractResults(
    const proto::BbObliviousSignatureResponse& response,
    const proto::BbObliviousSignatureRequest& request,
    const proto::BbObliviousSignatureRequestPrivateState& request_state) {
  // Unmask and extract the signatures.
  ASSIGN_OR_RETURN(std::vector<ECPoint> masked_prf_values,
                   ParseECPointVectorProto(ctx_, ec_group_,
                                           response.masked_signature_values()));
  std::vector<BigNum> as =
      ParseBigNumVectorProto(ctx_, request_state.private_as());

  std::vector<ECPoint> prf_values;
  prf_values.reserve(masked_prf_values.size());

  for (size_t i = 0; i < masked_prf_values.size(); ++i) {
    ASSIGN_OR_RETURN(ECPoint prf_value, masked_prf_values[i].Mul(as[i]));
    prf_values.push_back(std::move(prf_value));
  }

  return std::move(prf_values);
}

// Generates the challenge for the Request proof using the Fiat-Shamir
// heuristic.
StatusOr<BigNum> BbObliviousSignature::GenerateRequestProofChallenge(
    const proto::BbObliviousSignatureRequestProof::Statement& proof_statement,
    const proto::BbObliviousSignatureRequestProof::Message1& proof_message_1) {
  BigNum challenge_bound =
      ctx_->One().Lshift(parameters_proto_.challenge_length_bits());

  // Note that the random oracle prefix is implicitly included as part of the
  // parameters being serialized in the statement proto. We skip including it
  // again here to avoid unnecessary duplication.
  std::string challenge_string =
      "BbObliviousSignature::GenerateResponseProofChallenge";

  auto challenge_sos =
      std::make_unique<google::protobuf::io::StringOutputStream>(
          &challenge_string);
  auto challenge_cos =
      std::make_unique<google::protobuf::io::CodedOutputStream>(
          challenge_sos.get());
  challenge_cos->SetSerializationDeterministic(true);
  challenge_cos->WriteVarint64(proof_statement.ByteSizeLong());
  if (!proof_statement.SerializeToCodedStream(challenge_cos.get())) {
    return absl::InternalError(
        "BbObliviousSignature::GenerateRequestProofChallenge: Failed to "
        "serialize statement.");
  }

  challenge_cos->WriteVarint64(proof_message_1.ByteSizeLong());
  if (!proof_message_1.SerializeToCodedStream(challenge_cos.get())) {
    return absl::InternalError(
        "BbObliviousSignature::GenerateRequestProofChallenge: Failed to "
        "serialize proof_message_1.");
  }

  // Delete the CodedOutputStream and StringOutputStream to make sure they are
  // cleaned up before hashing.
  challenge_cos.reset();
  challenge_sos.reset();

  return ctx_->RandomOracleSha512(challenge_string, challenge_bound);
}

// Generates the challenge for the Response proof using the Fiat-Shamir
// heuristic.
StatusOr<BigNum> BbObliviousSignature::GenerateResponseProofChallenge(
    const proto::BbObliviousSignaturePublicKey& public_key,
    const PedersenOverZn::Commitment& commit_messages,
    const PedersenOverZn::Commitment& commit_rs,
    const proto::BbObliviousSignatureRequest& request,
    const proto::BbObliviousSignatureResponse& response,
    const PedersenOverZn::Commitment& commit_betas,
    const proto::BbObliviousSignatureResponseProof::Message1& proof_message_1) {
  BigNum challenge_bound =
      ctx_->One().Lshift(parameters_proto_.challenge_length_bits());

  // Generate the statement
  proto::BbObliviousSignatureResponseProof::Statement statement;
  *statement.mutable_parameters() = parameters_proto_;
  *statement.mutable_public_key() = public_key;
  statement.set_commit_messages(commit_messages.ToBytes());
  statement.set_commit_rs(commit_rs.ToBytes());
  *statement.mutable_request() = request;
  *statement.mutable_response() = response;
  statement.set_commit_betas(commit_betas.ToBytes());

  // Note that the random oracle prefix is implicitly included as part of the
  // parameters being serialized in the statement proto. We skip including it
  // again here to avoid unnecessary duplication.
  std::string challenge_string =
      "BbObliviousSignature::GenerateResponseProofChallenge";

  auto challenge_sos =
      std::make_unique<google::protobuf::io::StringOutputStream>(
          &challenge_string);
  auto challenge_cos =
      std::make_unique<google::protobuf::io::CodedOutputStream>(
          challenge_sos.get());
  challenge_cos->SetSerializationDeterministic(true);
  challenge_cos->WriteVarint64(statement.ByteSizeLong());
  if (!statement.SerializeToCodedStream(challenge_cos.get())) {
    return absl::InternalError(
        "BbObliviousSignature::GenerateResponseProofChallenge: Failed to "
        "serialize statement.");
  }

  challenge_cos->WriteVarint64(proof_message_1.ByteSizeLong());
  if (!proof_message_1.SerializeToCodedStream(challenge_cos.get())) {
    return absl::InternalError(
        "BbObliviousSignature::GenerateResponseProofChallenge: Failed to "
        "serialize proof_message_1.");
  }

  // Delete the CodedOutputStream and StringOutputStream to make sure they are
  // cleaned up before hashing.
  challenge_cos.reset();
  challenge_sos.reset();

  return ctx_->RandomOracleSha512(challenge_string, challenge_bound);
}

}  // namespace private_join_and_compute
