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

#ifndef PRIVATE_JOIN_AND_COMPUTE_CRYPTO_DODIS_YAMPOLSKIY_PRF_BB_OBLIVIOUS_SIGNATURE_H_
#define PRIVATE_JOIN_AND_COMPUTE_CRYPTO_DODIS_YAMPOLSKIY_PRF_BB_OBLIVIOUS_SIGNATURE_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/camenisch_shoup.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.pb.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"

namespace private_join_and_compute {

// Implements an oblivious signing protocol for the Boneh-Boyen signature [1]
// with private-key-verification. The Boneh-Boyen scheme is defined over a group
// where the q-SDHI assumption holds. Let g be a generator for this group. Then
// the signing/verification key consists of a pair (k,y), each consisting of
// secret exponents in the group. A signature is provided on a pair (m,r) where
// m is a message and r is a nonce. The signature has the form g^1/(m + k + yr).
// As discussed in [1], this signature is unforgeable as long as r is chosen at
// random.
//
// We implement an oblivious evaluation protocol for this signature on committed
// m and r. We also support batched signature issuance.
//
// To compute it obliviously, the server generates keys k and y, and encrypts
// them using a variant of the Camenisch-Shoup encryption scheme to get ct_k.
// When the receiver wants the signature evaluated on (m,r), the receiver
// homomorphically computes ct_(masked_(m+k+yr)) from ct_k and ct_y, and proves
// that ct_(masked_(m+k+yr)) was correctly generated with appropriately chosen
// masks. The server decrypts this ciphertext and computes
// g^(1/masked_(m+k+yr)), sending this back to the receiver with a proof that it
// was computed correctly. The client unmasks this value to recover the
// signature, namely g^1/(m + k + yr).
//
// The concrete masking is masked_(m+k+yr) = (m+k+yr)*a + b*q, where a and b are
// two random numbers of particular bitlengths, and where q is the order of g.
// The proofs sent by the sender and receiver are each sigma protocols that can
// be made non-interactive using the Fiat-Shamir heuristic.
//
// Note that this library has an important caveat: it does not enforce that r is
// generated randomly by the signature receiver. It is up to the user of this
// library to ensure that the enclosing context guarantees that r is randomly
// generated.
//
// [1] "Short Signatures Without Random Oracles", Boneh D., Boyen X.
// https://ai.stanford.edu/~xb/eurocrypt04a/bbsigs.pdf
class BbObliviousSignature {
 public:
  // Creates an object for producing Boneh-Boyen signatures. Fails if the
  // provided pointers are nullptr, or if the Pedersen commitment scheme is
  // inconsistent with the Camenisch-Shoup encryption scheme. The max number
  // of messages in a batch will be the Pedersen Batch size.
  static StatusOr<std::unique_ptr<BbObliviousSignature>> Create(
      proto::BbObliviousSignatureParameters parameters_proto, Context* ctx,
      ECGroup* ec_group, PublicCamenischShoup* public_camenisch_shoup,
      PedersenOverZn* pedersen);

  // Generates a new key pair for this BB Oblivious Signature scheme. The
  // modulus n for Camenisch Shoup will be pulled from the parameters.
  //
  StatusOr<std::tuple<proto::BbObliviousSignaturePublicKey,
                      proto::BbObliviousSignaturePrivateKey>>
  GenerateKeys();

  // Generates an oblivious signature request on a batch of messages. An
  // important security caveat is that each r should be collaboratively
  // generated or generated honestly somehow by the enclosing protocol.
  StatusOr<std::tuple<proto::BbObliviousSignatureRequest,
                      proto::BbObliviousSignatureRequestProof,
                      proto::BbObliviousSignatureRequestPrivateState>>
  GenerateRequestAndProof(
      const std::vector<BigNum>& messages, const std::vector<BigNum>& rs,
      const proto::BbObliviousSignaturePublicKey& public_key,
      const PedersenOverZn::CommitmentAndOpening& commit_and_open_messages,
      const PedersenOverZn::CommitmentAndOpening& commit_and_open_rs);

  // Verifies a signature request and proof.
  Status VerifyRequest(
      const proto::BbObliviousSignaturePublicKey& public_key,
      const proto::BbObliviousSignatureRequest& request,
      const proto::BbObliviousSignatureRequestProof& request_proof,
      const PedersenOverZn::Commitment& commit_messages,
      const PedersenOverZn::Commitment& commit_rs);

  // Generates an BB Oblivious Signature Response and proof.
  StatusOr<std::tuple<proto::BbObliviousSignatureResponse,
                      proto::BbObliviousSignatureResponseProof>>
  GenerateResponseAndProof(
      const proto::BbObliviousSignatureRequest& request,
      const proto::BbObliviousSignaturePublicKey& public_key,
      const proto::BbObliviousSignaturePrivateKey& private_key,
      const PedersenOverZn::Commitment& commit_messages,
      const PedersenOverZn::Commitment& commit_rs,
      PrivateCamenischShoup* private_camenisch_shoup);

  Status VerifyResponse(
      const proto::BbObliviousSignaturePublicKey& public_key,
      const proto::BbObliviousSignatureResponse& response,
      const proto::BbObliviousSignatureResponseProof& response_proof,
      const proto::BbObliviousSignatureRequest& request,
      const PedersenOverZn::Commitment& commit_messages,
      const PedersenOverZn::Commitment& commit_rs);

  // Extracts the signatures values. Assumes the response proof has already been
  // verified. Each response is a signature on corresponding (m, r) committed by
  // the requester.
  StatusOr<std::vector<ECPoint>> ExtractResults(
      const proto::BbObliviousSignatureResponse& response,
      const proto::BbObliviousSignatureRequest& request,
      const proto::BbObliviousSignatureRequestPrivateState& request_state);

 private:
  BbObliviousSignature(proto::BbObliviousSignatureParameters parameters_proto,
                       Context* ctx, ECGroup* ec_group, ECPoint base_g,
                       PublicCamenischShoup* public_camenisch_shoup,
                       PedersenOverZn* pedersen)
      : parameters_proto_(std::move(parameters_proto)),
        ctx_(ctx),
        ec_group_(ec_group),
        base_g_(std::move(base_g)),
        public_camenisch_shoup_(public_camenisch_shoup),
        pedersen_(pedersen) {}

  // Generates the challenge for the Request proof using the Fiat-Shamir
  // heuristic.
  StatusOr<BigNum> GenerateRequestProofChallenge(
      const proto::BbObliviousSignatureRequestProof::Statement& proof_statement,
      const proto::BbObliviousSignatureRequestProof::Message1& proof_message_1);

  // Generates the challenge for the Response proof using the Fiat-Shamir
  // heuristic.
  StatusOr<BigNum> GenerateResponseProofChallenge(
      const proto::BbObliviousSignaturePublicKey& public_key,
      const PedersenOverZn::Commitment& commit_messages,
      const PedersenOverZn::Commitment& commit_rs,
      const proto::BbObliviousSignatureRequest& request,
      const proto::BbObliviousSignatureResponse& response,
      const PedersenOverZn::Commitment& commit_betas,
      const proto::BbObliviousSignatureResponseProof::Message1&
          proof_message_1);

  proto::BbObliviousSignatureParameters parameters_proto_;
  Context* ctx_;
  ECGroup* ec_group_;
  ECPoint base_g_;
  PublicCamenischShoup* public_camenisch_shoup_;
  PedersenOverZn* pedersen_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_CRYPTO_DODIS_YAMPOLSKIY_PRF_BB_OBLIVIOUS_SIGNATURE_H_
