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

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.pb.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "src/google/protobuf/io/coded_stream.h"
#include "src/google/protobuf/io/zero_copy_stream_impl_lite.h"

namespace private_join_and_compute {

StatusOr<std::unique_ptr<DyVerifiableRandomFunction>>
DyVerifiableRandomFunction::Create(proto::DyVrfParameters parameters_proto,
                                   Context* context, ECGroup* ec_group,
                                   PedersenOverZn* pedersen) {
  if (parameters_proto.security_parameter() <= 0) {
    return absl::InvalidArgumentError(
        "parameters.security_parameter must be >= 0");
  }
  if (parameters_proto.challenge_length_bits() <= 0) {
    return absl::InvalidArgumentError(
        "parameters.challenge_length_bits must be >= 0");
  }

  ASSIGN_OR_RETURN(ECPoint dy_prf_base_g,
                   ec_group->CreateECPoint(parameters_proto.dy_prf_base_g()));

  return absl::WrapUnique(new DyVerifiableRandomFunction(
      std::move(parameters_proto), context, ec_group, std::move(dy_prf_base_g),
      pedersen));
}

StatusOr<std::tuple<proto::DyVrfPublicKey, proto::DyVrfPrivateKey,
                    proto::DyVrfGenerateKeysProof>>
DyVerifiableRandomFunction::GenerateKeyPair() {
  // Generate a fresh key, and commit to it with respect to each Pedersen
  // generator.
  BigNum key = ec_group_->GeneratePrivateKey();

  int num_copies = pedersen_->gs().size();
  ASSIGN_OR_RETURN(PedersenOverZn::CommitmentAndOpening commit_and_open_key,
                   pedersen_->Commit(std::vector<BigNum>(num_copies, key)));

  DyVerifiableRandomFunction::PublicKey public_key{
      commit_and_open_key.commitment  // commit_key
  };
  DyVerifiableRandomFunction::PrivateKey private_key{
      key,                         // key
      commit_and_open_key.opening  // open_key
  };

  proto::DyVrfPublicKey public_key_proto = DyVrfPublicKeyToProto(public_key);
  proto::DyVrfPrivateKey private_key_proto =
      DyVrfPrivateKeyToProto(private_key);

  // Generate the keys proof. This proof is a sigma protocol that proves
  // knowledge of the key, and also that the same key has been committed in each
  // component of the batched Pedersen commitment scheme. Furthermore, this
  // proof shows that the key is bounded-with-slack, using the range proof
  // feature of sigma protocols (i.e. checking the size of the masked dummy
  // opening to the key). The proven bound on the key is ec_group_order *
  // 2^(challenge_length + security_parameter).
  //
  // These properties are sufficient for the key to be safe for use downstream.
  //
  // As in all sigma protocols, this proof proceeds by the prover generating
  // dummy values for all the secret exponents (here, these are the key and the
  // commitment randomness), and then creating a dummy commitment to the key
  // using the dummy values. The sigma protocol then hashes this dummy
  // commitment together with the proof statement (i.e. the original commitment)
  // to produce a challenge using the Fiat-Shamir heuristic. Given this
  // challenge, the prover then sends the receiver "masked_dummy_values" as
  // dummy_value + (challenge * real_value) for each of the secret exponents.
  // The verifier can then use these masked_dummy_values to verify the proof.

  // Generate dummy key and opening.
  BigNum dummy_key_bound =
      ec_group_->GetOrder().Lshift(parameters_proto_.challenge_length_bits() +
                                   parameters_proto_.security_parameter());
  BigNum dummy_opening_bound =
      pedersen_->n().Lshift(parameters_proto_.challenge_length_bits() +
                            parameters_proto_.security_parameter());
  BigNum dummy_key = context_->GenerateRandLessThan(dummy_key_bound);
  BigNum dummy_opening = context_->GenerateRandLessThan(dummy_opening_bound);
  std::vector<BigNum> dummy_key_vector =
      std::vector<BigNum>(num_copies, dummy_key);
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment dummy_commit_prf_key,
                   pedersen_->CommitWithRand(dummy_key_vector, dummy_opening));

  // Create Statement and first message, and generate the challenge.
  proto::DyVrfGenerateKeysProof::Statement statement;
  *statement.mutable_parameters() = parameters_proto_;
  *statement.mutable_public_key() = public_key_proto;

  proto::DyVrfGenerateKeysProof::Message1 message_1;
  *message_1.mutable_dummy_commit_prf_key() = dummy_commit_prf_key.ToBytes();

  ASSIGN_OR_RETURN(BigNum challenge,
                   GenerateChallengeForGenerateKeysProof(statement, message_1));

  // Create the masked_dummy_opening values.
  BigNum masked_dummy_prf_key = dummy_key + (key.Mul(challenge));
  BigNum masked_dummy_opening =
      dummy_opening + (commit_and_open_key.opening.Mul(challenge));

  // Package the values into the proof proto.
  proto::DyVrfGenerateKeysProof generate_keys_proof;

  generate_keys_proof.set_challenge(challenge.ToBytes());
  generate_keys_proof.mutable_message_2()->set_masked_dummy_prf_key(
      masked_dummy_prf_key.ToBytes());
  generate_keys_proof.mutable_message_2()->set_masked_dummy_opening(
      masked_dummy_opening.ToBytes());

  return {std::make_tuple(std::move(public_key_proto),
                          std::move(private_key_proto),
                          std::move(generate_keys_proof))};
}

// Verifies that the public key has a bounded key, and commits to the same key
// in each component of the Pedersen batch commitment.
Status DyVerifiableRandomFunction::VerifyGenerateKeysProof(
    const proto::DyVrfPublicKey& public_key,
    const proto::DyVrfGenerateKeysProof& proof) {
  // Deserialize components of the public key and proof
  BigNum commit_prf_key = context_->CreateBigNum(public_key.commit_prf_key());
  BigNum challenge_from_proof = context_->CreateBigNum(proof.challenge());
  BigNum masked_dummy_prf_key =
      context_->CreateBigNum(proof.message_2().masked_dummy_prf_key());
  BigNum masked_dummy_opening =
      context_->CreateBigNum(proof.message_2().masked_dummy_opening());

  // Verify the bounds on masked_dummy values
  BigNum masked_dummy_prf_key_bound =
      ec_group_->GetOrder().Lshift(parameters_proto_.challenge_length_bits() +
                                   parameters_proto_.security_parameter() + 1);
  if (masked_dummy_prf_key > masked_dummy_prf_key_bound) {
    return absl::InvalidArgumentError(absl::StrCat(
        "DyVerifiableRandomFunction::VerifyGenerateKeysProof: "
        "masked_dummy_prf_key is larger than the bound. Supplied value: ",
        masked_dummy_prf_key.ToDecimalString(),
        ". bound: ", masked_dummy_prf_key_bound.ToDecimalString()));
  }

  // Regenerate dummy values from the masked_dummy values and the challenge in
  // the proof.
  std::vector<BigNum> masked_dummy_prf_key_vector =
      std::vector<BigNum>(pedersen_->gs().size(), masked_dummy_prf_key);
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment masked_dummy_prf_key_commitment,
                   pedersen_->CommitWithRand(masked_dummy_prf_key_vector,
                                             masked_dummy_opening));

  ASSIGN_OR_RETURN(PedersenOverZn::Commitment commit_keys_to_challenge_inverse,
                   pedersen_->Multiply(commit_prf_key, challenge_from_proof)
                       .ModInverse(pedersen_->n()));
  PedersenOverZn::Commitment dummy_commit_prf_key = pedersen_->Add(
      commit_keys_to_challenge_inverse, masked_dummy_prf_key_commitment);

  // Regenerate the challenge and verify that it matches the challenge in the
  // proof.
  proto::DyVrfGenerateKeysProof::Statement statement;
  proto::DyVrfGenerateKeysProof::Message1 message_1;

  *statement.mutable_parameters() = parameters_proto_;
  *statement.mutable_public_key() = public_key;

  message_1.set_dummy_commit_prf_key(dummy_commit_prf_key.ToBytes());

  ASSIGN_OR_RETURN(BigNum reconstructed_challenge,
                   GenerateChallengeForGenerateKeysProof(statement, message_1));

  if (reconstructed_challenge != challenge_from_proof) {
    return absl::InvalidArgumentError(absl::StrCat(
        "DyVerifiableRandomFunction::VerifyGenerateKeysProof: Failed to verify "
        " proof. Challenge in proof (",
        challenge_from_proof.ToDecimalString(),
        ") does not match reconstructed challenge (",
        reconstructed_challenge.ToDecimalString(), ")."));
  }

  return absl::OkStatus();
}

// Generates the challenge for the GenerateKeysProof using the Fiat-Shamir
// heuristic.
StatusOr<BigNum>
DyVerifiableRandomFunction::GenerateChallengeForGenerateKeysProof(
    const proto::DyVrfGenerateKeysProof::Statement& statement,
    const proto::DyVrfGenerateKeysProof::Message1& message_1) {
  // Note that the random oracle prefix is implicitly included as part of the
  // parameters being serialized in the statement proto. We skip including it
  // again here to avoid unnecessary duplication.
  std::string challenge_string =
      "DyVerifiableRandomFunction::GenerateChallengeForGenerateKeysProof";
  auto challenge_sos =
      std::make_unique<google::protobuf::io::StringOutputStream>(
          &challenge_string);
  auto challenge_cos =
      std::make_unique<google::protobuf::io::CodedOutputStream>(
          challenge_sos.get());
  challenge_cos->SetSerializationDeterministic(true);
  challenge_cos->WriteVarint64(statement.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(statement));

  challenge_cos->WriteVarint64(message_1.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(message_1));

  BigNum challenge_bound =
      context_->One().Lshift(parameters_proto_.challenge_length_bits());

  // Delete the serialization objects to make sure they clean up and write.
  challenge_cos.reset();
  challenge_sos.reset();

  return context_->RandomOracleSha512(challenge_string, challenge_bound);
}

// Applies the DY VRF to a given batch of messages.
StatusOr<std::vector<ECPoint>> DyVerifiableRandomFunction::Apply(
    absl::Span<const BigNum> messages,
    const proto::DyVrfPrivateKey& private_key) {
  std::vector<ECPoint> dy_prf_evaluations;
  dy_prf_evaluations.reserve(messages.size());

  ASSIGN_OR_RETURN(DyVerifiableRandomFunction::PrivateKey parsed_private_key,
                   ParseDyVrfPrivateKeyProto(context_, private_key));

  for (const BigNum& message : messages) {
    // f(m) = g^(1/(key+m))
    ASSIGN_OR_RETURN(
        BigNum key_plus_message_inverse,
        (message + parsed_private_key.key).ModInverse(ec_group_->GetOrder()));
    ASSIGN_OR_RETURN(ECPoint prf_evaluation,
                     dy_prf_base_g_.Mul(key_plus_message_inverse));
    dy_prf_evaluations.push_back(std::move(prf_evaluation));
  }

  return std::move(dy_prf_evaluations);
}

StatusOr<std::pair<
    std::unique_ptr<DyVerifiableRandomFunction::ApplyProof::Message1>,
    std::unique_ptr<
        DyVerifiableRandomFunction::ApplyProof::Message1PrivateState>>>
DyVerifiableRandomFunction::GenerateApplyProofMessage1(
    absl::Span<const BigNum> messages,
    absl::Span<const ECPoint> prf_evaluations,
    const PedersenOverZn::CommitmentAndOpening& commit_and_open_messages,
    const DyVerifiableRandomFunction::PublicKey& public_key,
    const DyVerifiableRandomFunction::PrivateKey& private_key) {
  BigNum dummy_message_bound =
      ec_group_->GetOrder().Lshift(parameters_proto_.security_parameter() +
                                   parameters_proto_.challenge_length_bits());
  BigNum dummy_opening_bound =
      pedersen_->n().Lshift(parameters_proto_.security_parameter() +
                            parameters_proto_.challenge_length_bits());

  // The proof is relative to a homomorphically added commitment of k + m.

  // Generate dummy values for each message and the key, and create a dummy
  // commitment to the vector of dummy k+m values.

  BigNum dummy_key = context_->GenerateRandLessThan(dummy_message_bound);

  std::vector<BigNum> dummy_messages_plus_key;
  dummy_messages_plus_key.reserve(messages.size());

  for (size_t i = 0; i < pedersen_->gs().size(); ++i) {
    if (i < messages.size()) {
      dummy_messages_plus_key.push_back(
          context_->GenerateRandLessThan(dummy_message_bound) + dummy_key);
    } else {
      // If there's fewer messages than the number of Pedersen generators,
      // pretend the message was 0. Leveraging the fact that the same key is
      // committed w.r.t each Pedersen generator in the VRF public key, it's
      // sufficient to just use dummy_key here.
      dummy_messages_plus_key.push_back(dummy_key);
    }
  }

  PedersenOverZn::Opening dummy_opening =
      context_->GenerateRandLessThan(dummy_opening_bound);
  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment commit_dummy_messages_plus_key,
      pedersen_->CommitWithRand(dummy_messages_plus_key, dummy_opening));

  // Generate dummy_dy_prf_base_gs as (prf_evaluation ^ dummy_message_plus_key)
  std::vector<ECPoint> dummy_dy_prf_base_gs;
  dummy_dy_prf_base_gs.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    ASSIGN_OR_RETURN(ECPoint dummy_dy_prf_base_g,
                     prf_evaluations[i].Mul(dummy_messages_plus_key[i]));
    dummy_dy_prf_base_gs.push_back(std::move(dummy_dy_prf_base_g));
  }

  ApplyProof::Message1 message_1 = {std::move(commit_dummy_messages_plus_key),
                                    std::move(dummy_dy_prf_base_gs)};

  ApplyProof::Message1PrivateState private_state = {
      std::move(dummy_messages_plus_key), std::move(dummy_key),
      std::move(dummy_opening)};

  return std::make_pair(
      std::make_unique<ApplyProof::Message1>(std::move(message_1)),
      std::make_unique<ApplyProof::Message1PrivateState>(
          std::move(private_state)));
}

// Applies the DY VRF to a given batch of messages, producing the PRF output
// and proof. Allows injecting the commitment and opening to the messages.
StatusOr<std::unique_ptr<DyVerifiableRandomFunction::ApplyProof::Message2>>
DyVerifiableRandomFunction::GenerateApplyProofMessage2(
    absl::Span<const BigNum> messages,
    absl::Span<const ECPoint> prf_evaluations,
    const PedersenOverZn::CommitmentAndOpening& commit_and_open_messages,
    const DyVerifiableRandomFunction::PublicKey& public_key,
    const DyVerifiableRandomFunction::PrivateKey& private_key,
    const DyVerifiableRandomFunction::ApplyProof::Message1& message_1,
    const DyVerifiableRandomFunction::ApplyProof::Message1PrivateState&
        private_state,
    const BigNum& challenge) {
  BigNum masked_dummy_key =
      private_state.dummy_key + (private_key.key.Mul(challenge));

  PedersenOverZn::Opening masked_dummy_opening =
      private_state.dummy_opening +
      ((private_key.commit_key_opening + commit_and_open_messages.opening)
           .Mul(challenge));
  std::vector<BigNum> masked_dummy_messages_plus_key;
  masked_dummy_messages_plus_key.reserve(pedersen_->gs().size());
  for (size_t i = 0; i < pedersen_->gs().size(); ++i) {
    if (i < messages.size()) {
      masked_dummy_messages_plus_key.push_back(
          private_state.dummy_messages_plus_key[i] +
          ((messages[i] + private_key.key).Mul(challenge)));
    } else {
      masked_dummy_messages_plus_key.push_back(masked_dummy_key);
    }
  }

  ApplyProof::Message2 message_2 = {std::move(masked_dummy_messages_plus_key),
                                    std::move(masked_dummy_opening)};

  return std::make_unique<ApplyProof::Message2>(std::move(message_2));
}

StatusOr<proto::DyVrfApplyProof> DyVerifiableRandomFunction::GenerateApplyProof(
    absl::Span<const BigNum> messages,
    absl::Span<const ECPoint> prf_evaluations,
    const proto::DyVrfPublicKey& public_key,
    const proto::DyVrfPrivateKey& private_key,
    const PedersenOverZn::CommitmentAndOpening& commit_and_open_messages) {
  ASSIGN_OR_RETURN(PublicKey public_key_parsed,
                   ParseDyVrfPublicKeyProto(context_, public_key));
  ASSIGN_OR_RETURN(PrivateKey private_key_parsed,
                   ParseDyVrfPrivateKeyProto(context_, private_key));

  proto::DyVrfApplyProof proof_proto;

  std::unique_ptr<DyVerifiableRandomFunction::ApplyProof::Message1>
      proof_message_1;
  std::unique_ptr<DyVerifiableRandomFunction::ApplyProof::Message1PrivateState>
      proof_message_1_private_state;

  ASSIGN_OR_RETURN(std::tie(proof_message_1, proof_message_1_private_state),
                   GenerateApplyProofMessage1(
                       messages, prf_evaluations, commit_and_open_messages,
                       public_key_parsed, private_key_parsed));

  ASSIGN_OR_RETURN(*proof_proto.mutable_message_1(),
                   DyVrfApplyProofMessage1ToProto(*proof_message_1));

  ASSIGN_OR_RETURN(BigNum challenge, GenerateApplyProofChallenge(
                                         prf_evaluations, public_key,
                                         commit_and_open_messages.commitment,
                                         proof_proto.message_1()));

  ASSIGN_OR_RETURN(
      std::unique_ptr<DyVerifiableRandomFunction::ApplyProof::Message2>
          proof_message_2,
      GenerateApplyProofMessage2(messages, prf_evaluations,
                                 commit_and_open_messages, public_key_parsed,
                                 private_key_parsed, *proof_message_1,
                                 *proof_message_1_private_state, challenge));
  *proof_proto.mutable_message_2() =
      DyVrfApplyProofMessage2ToProto(*proof_message_2);

  return std::move(proof_proto);
}

// Verifies that vrf_output was produced by applying a DY VRF with the
// supplied public key on the supplied committed messages.
Status DyVerifiableRandomFunction::VerifyApplyProof(
    absl::Span<const ECPoint> prf_evaluations,
    const proto::DyVrfPublicKey& public_key,
    const PedersenOverZn::Commitment& commit_messages,
    const proto::DyVrfApplyProof& proof) {
  ASSIGN_OR_RETURN(PublicKey public_key_parsed,
                   ParseDyVrfPublicKeyProto(context_, public_key));
  ASSIGN_OR_RETURN(ApplyProof::Message1 message_1,
                   ParseDyVrfApplyProofMessage1Proto(context_, ec_group_,
                                                     proof.message_1()));
  ASSIGN_OR_RETURN(
      ApplyProof::Message2 message_2,
      ParseDyVrfApplyProofMessage2Proto(context_, proof.message_2()));

  // Check input sizes.
  if (prf_evaluations.size() > pedersen_->gs().size()) {
    return absl::InvalidArgumentError(
        "DyVerifiableRandomFunction::VerifyApplyProof: Number of "
        "prf_evaluations is "
        "greater than the number of Pedersen generators.");
  }
  if (prf_evaluations.size() != message_1.dummy_dy_prf_base_gs.size()) {
    return absl::InvalidArgumentError(
        "DyVerifiableRandomFunction::VerifyApplyProof: Number of "
        "prf_evaluations is different from the number of dummy_dy_prf_base_gs "
        "in the proof.");
  }
  if (pedersen_->gs().size() !=
      message_2.masked_dummy_messages_plus_key.size()) {
    return absl::InvalidArgumentError(
        "DyVerifiableRandomFunction::VerifyApplyProof: Number of pedersen_gs "
        "is different from the number of masked_dummy_messages_plus_keys in "
        "the proof.");
  }

  // Note that even if there were fewer messages than Pedersen generators, the
  // logic below  handles this completely dynamically and safely. This is
  // because no matter what the prover does for the "extra" generators, it
  // doesn't allow breaking soundness for the values committed in the other
  // generators.

  // Invoke GenerateApplyProofChallenge if challenge is not already specified
  // as a parameter.
  ASSIGN_OR_RETURN(BigNum challenge, GenerateApplyProofChallenge(
                                         prf_evaluations, public_key,
                                         commit_messages, proof.message_1()));

  // Verify the bit lengths of the masked values in the proof.
  for (const auto& masked_value : message_2.masked_dummy_messages_plus_key) {
    // There is an extra "+1" to account for summation.
    if (masked_value.BitLength() >
        (ec_group_->GetOrder().BitLength() +
         parameters_proto_.challenge_length_bits() +
         parameters_proto_.security_parameter() + 2)) {
      return absl::InvalidArgumentError(
          "DyVerifiableRandomFunction::Verify: some masked value in the proof "
          "is larger than the admissable amount.");
    }
  }

  // Check properties hold for dummy_dy_prf_base_gs.
  ASSIGN_OR_RETURN(ECPoint dy_prf_base_g_to_challenge,
                   dy_prf_base_g_.Mul(challenge));
  for (size_t i = 0; i < prf_evaluations.size(); ++i) {
    // Let sigma be the prf evaluation. Then we must check (in multiplicative
    // notation):
    // sigma^(masked_key_plus_message) =
    //   (dummy_dy_prf_base_gs * (dy_prf_base_g^challenge))
    ASSIGN_OR_RETURN(
        ECPoint check_prf_left_hand_side,
        prf_evaluations[i].Mul(message_2.masked_dummy_messages_plus_key[i]));

    ASSIGN_OR_RETURN(
        ECPoint check_prf_right_hand_side,
        message_1.dummy_dy_prf_base_gs[i].Add(dy_prf_base_g_to_challenge));
    if (check_prf_left_hand_side != check_prf_right_hand_side) {
      return absl::InvalidArgumentError(
          absl::StrCat("DyVerifiableRandomFunction::Verify: failed to verify "
                       "prf_evaluations[",
                       i, "]."));
    }
  }
  // Check properties hold for the commitments to dummy values.
  PedersenOverZn::Commitment commit_messages_plus_key_to_challenge =
      pedersen_->Multiply(
          pedersen_->Add(commit_messages, public_key_parsed.commit_key),
          challenge);

  ASSIGN_OR_RETURN(
      PedersenOverZn::Commitment masked_dummy_commitment,
      pedersen_->CommitWithRand(message_2.masked_dummy_messages_plus_key,
                                message_2.masked_dummy_opening));
  PedersenOverZn::Commitment commitment_check_right_hand_side =
      pedersen_->Add(message_1.commit_dummy_messages_plus_key,
                     commit_messages_plus_key_to_challenge);

  if (masked_dummy_commitment != commitment_check_right_hand_side) {
    return absl::InvalidArgumentError(
        "DyVerifiableRandomFunction::Verify: failed to verify "
        "commitment to keys and messages are consistent with prfs.");
  }

  return absl::OkStatus();
}

StatusOr<BigNum> DyVerifiableRandomFunction::GenerateApplyProofChallenge(
    absl::Span<const ECPoint> prf_evaluations,
    const proto::DyVrfPublicKey& public_key,
    const PedersenOverZn::Commitment& commit_messages,
    const proto::DyVrfApplyProof::Message1& message_1) {
  // Generate the statement
  proto::DyVrfApplyProof::Statement statement;
  *statement.mutable_parameters() = parameters_proto_;
  *statement.mutable_public_key() = public_key;
  statement.set_commit_messages(commit_messages.ToBytes());
  ASSIGN_OR_RETURN(*statement.mutable_prf_evaluations(),
                   ECPointVectorToProto(prf_evaluations));

  // Note that the random oracle prefix is implicitly included as part of the
  // parameters being serialized in the statement proto. We skip including it
  // again here to avoid unnecessary duplication.
  std::string challenge_string =
      "DyVerifiableRandomFunction::GenerateApplyProofChallenge";
  auto challenge_sos =
      std::make_unique<google::protobuf::io::StringOutputStream>(
          &challenge_string);
  auto challenge_cos =
      std::make_unique<google::protobuf::io::CodedOutputStream>(
          challenge_sos.get());
  challenge_cos->SetSerializationDeterministic(true);
  challenge_cos->WriteVarint64(statement.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(statement));

  challenge_cos->WriteVarint64(message_1.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(message_1));

  BigNum challenge_bound =
      context_->One().Lshift(parameters_proto_.challenge_length_bits());

  // Delete the serialization objects to make sure they clean up and write.
  challenge_cos.reset();
  challenge_sos.reset();

  return context_->RandomOracleSha512(challenge_string, challenge_bound);
}

proto::DyVrfPublicKey DyVerifiableRandomFunction::DyVrfPublicKeyToProto(
    const DyVerifiableRandomFunction::PublicKey& public_key) {
  proto::DyVrfPublicKey public_key_proto;
  public_key_proto.set_commit_prf_key(public_key.commit_key.ToBytes());
  return public_key_proto;
}
proto::DyVrfPrivateKey DyVerifiableRandomFunction::DyVrfPrivateKeyToProto(
    const DyVerifiableRandomFunction::PrivateKey& private_key) {
  proto::DyVrfPrivateKey private_key_proto;
  private_key_proto.set_prf_key(private_key.key.ToBytes());
  private_key_proto.set_open_commit_prf_key(
      private_key.commit_key_opening.ToBytes());
  return private_key_proto;
}
StatusOr<proto::DyVrfApplyProof::Message1>
DyVerifiableRandomFunction::DyVrfApplyProofMessage1ToProto(
    const DyVerifiableRandomFunction::ApplyProof::Message1& message_1) {
  proto::DyVrfApplyProof::Message1 message_1_proto;
  message_1_proto.set_commit_dummy_messages_plus_key(
      message_1.commit_dummy_messages_plus_key.ToBytes());
  ASSIGN_OR_RETURN(*message_1_proto.mutable_dummy_dy_prf_base_gs(),
                   ECPointVectorToProto(message_1.dummy_dy_prf_base_gs));
  return message_1_proto;
}
proto::DyVrfApplyProof::Message2
DyVerifiableRandomFunction::DyVrfApplyProofMessage2ToProto(
    const DyVerifiableRandomFunction::ApplyProof::Message2& message_2) {
  proto::DyVrfApplyProof::Message2 message_2_proto;
  *message_2_proto.mutable_masked_dummy_messages_plus_key() =
      BigNumVectorToProto(message_2.masked_dummy_messages_plus_key);
  message_2_proto.set_masked_dummy_opening(
      message_2.masked_dummy_opening.ToBytes());
  return message_2_proto;
}

StatusOr<DyVerifiableRandomFunction::PublicKey>
DyVerifiableRandomFunction::ParseDyVrfPublicKeyProto(
    Context* ctx, const proto::DyVrfPublicKey& public_key_proto) {
  BigNum commit_key = ctx->CreateBigNum(public_key_proto.commit_prf_key());
  return DyVerifiableRandomFunction::PublicKey{std::move(commit_key)};
}
StatusOr<DyVerifiableRandomFunction::PrivateKey>
DyVerifiableRandomFunction::ParseDyVrfPrivateKeyProto(
    Context* ctx, const proto::DyVrfPrivateKey& private_key_proto) {
  BigNum key = ctx->CreateBigNum(private_key_proto.prf_key());
  BigNum commit_key_opening =
      ctx->CreateBigNum(private_key_proto.open_commit_prf_key());
  return DyVerifiableRandomFunction::PrivateKey{std::move(key),
                                                std::move(commit_key_opening)};
}
StatusOr<DyVerifiableRandomFunction::ApplyProof::Message1>
DyVerifiableRandomFunction::ParseDyVrfApplyProofMessage1Proto(
    Context* ctx, ECGroup* ec_group,
    const proto::DyVrfApplyProof::Message1& message_1_proto) {
  BigNum commit_dummy_messages_plus_key =
      ctx->CreateBigNum(message_1_proto.commit_dummy_messages_plus_key());
  ASSIGN_OR_RETURN(std::vector<ECPoint> dummy_dy_prf_base_gs,
                   ParseECPointVectorProto(
                       ctx, ec_group, message_1_proto.dummy_dy_prf_base_gs()));
  return DyVerifiableRandomFunction::ApplyProof::Message1{
      std::move(commit_dummy_messages_plus_key),
      std::move(dummy_dy_prf_base_gs)};
}
StatusOr<DyVerifiableRandomFunction::ApplyProof::Message2>
DyVerifiableRandomFunction::ParseDyVrfApplyProofMessage2Proto(
    Context* ctx, const proto::DyVrfApplyProof::Message2& message_2_proto) {
  std::vector<BigNum> masked_dummy_messages_plus_key = ParseBigNumVectorProto(
      ctx, message_2_proto.masked_dummy_messages_plus_key());
  BigNum masked_dummy_opening =
      ctx->CreateBigNum(message_2_proto.masked_dummy_opening());
  return DyVerifiableRandomFunction::ApplyProof::Message2{
      std::move(masked_dummy_messages_plus_key),
      std::move(masked_dummy_opening)};
}

}  // namespace private_join_and_compute
