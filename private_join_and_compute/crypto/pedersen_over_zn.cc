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

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

PedersenOverZn::PedersenOverZn(
    Context* ctx, std::vector<BigNum> gs, const BigNum& h, const BigNum& n,
    std::unique_ptr<SimultaneousFixedBasesExp<ZnElement, ZnContext>>
        simultaneous_fixed_bases_exp)
    : ctx_(ctx),
      gs_(std::move(gs)),
      h_(h),
      n_(n),
      simultaneous_fixed_bases_exp_(std::move(simultaneous_fixed_bases_exp)) {}

StatusOr<std::unique_ptr<PedersenOverZn>> PedersenOverZn::Create(
    Context* ctx, std::vector<BigNum> gs, const BigNum& h, const BigNum& n,
    size_t num_simultaneous_exponentiations) {
  // The set of bases is gs_, with h_ appended at the end.
  std::vector<private_join_and_compute::BigNum> bases = gs;
  bases.push_back(h);

  std::unique_ptr<ZnContext> zn_context(new ZnContext({n}));

  int adjusted_num_simultaneous_exponentiations =
      std::min(bases.size(), num_simultaneous_exponentiations);

  auto simultaneous_fixed_bases_exp =
      SimultaneousFixedBasesExp<ZnElement, ZnContext>::Create(
          bases, ctx->One(), adjusted_num_simultaneous_exponentiations,
          std::move(zn_context))
          .value();

  return absl::WrapUnique(new PedersenOverZn(
      ctx, std::move(gs), h, n, std::move(simultaneous_fixed_bases_exp)));
}

StatusOr<std::unique_ptr<PedersenOverZn>> PedersenOverZn::FromProto(
    Context* ctx, const proto::PedersenParameters& parameters_proto,
    size_t num_simultaneous_exponentiations) {
  ASSIGN_OR_RETURN(PedersenOverZn::Parameters parameters,
                   PedersenOverZn::ParseParametersProto(ctx, parameters_proto));
  return PedersenOverZn::Create(ctx, std::move(parameters.gs), parameters.h,
                                parameters.n, num_simultaneous_exponentiations);
}

PedersenOverZn::~PedersenOverZn() = default;

StatusOr<PedersenOverZn::CommitmentAndOpening> PedersenOverZn::Commit(
    const std::vector<BigNum>& messages) const {
  BigNum r = ctx_->GenerateRandLessThan(n_);
  ASSIGN_OR_RETURN(auto commitment,
                   PedersenOverZn::CommitWithRand(messages, r));
  return {{std::move(commitment), std::move(r)}};
}

StatusOr<PedersenOverZn::Commitment> PedersenOverZn::CommitWithRand(
    const std::vector<BigNum>& messages, const BigNum& rand) const {
  if (messages.size() > gs_.size()) {
    return InvalidArgumentError(
        "PedersenOverZn::Commit() : too many messages provided");
  }

  for (const auto& message : messages) {
    if (!message.IsNonNegative()) {
      return InvalidArgumentError(
          "PedersenOverZn::Commit(): cannot commit to negative value.");
    }
  }
  if (!rand.IsNonNegative()) {
    return InvalidArgumentError(
        "PedersenOverZn::CommitWithRand(): randomness must be nonnegative.");
  }

  std::vector<BigNum> exponents = messages;
  // Add dummy 0s if fewer messages were provided.
  while (exponents.size() < gs_.size()) {
    exponents.push_back(ctx_->Zero());
  }
  // Push back the exponent for h_.
  exponents.push_back(rand);
  ASSIGN_OR_RETURN(BigNum product,
                   simultaneous_fixed_bases_exp_->SimultaneousExp(exponents));

  return std::move(product);
}

PedersenOverZn::Commitment PedersenOverZn::Add(
    const PedersenOverZn::Commitment& com1,
    const PedersenOverZn::Commitment& com2) const {
  return com1.ModMul(com2, n_);
}

PedersenOverZn::Commitment PedersenOverZn::Multiply(
    const PedersenOverZn::Commitment& com, const BigNum& scalar) const {
  return com.ModExp(scalar, n_);
}

StatusOr<bool> PedersenOverZn::Verify(
    const PedersenOverZn::Commitment& commitment,
    const std::vector<BigNum>& messages,
    const PedersenOverZn::Opening& opening) const {
  if (messages.size() > gs_.size()) {
    return InvalidArgumentError(
        "PedersenOverZn::Verify() : too many messages provided");
  }

  for (const auto& message : messages) {
    if (!message.IsNonNegative()) {
      return InvalidArgumentError(
          "PedersenOverZn::Verify(): message in the opening is negative.");
    }
  }
  if (!opening.IsNonNegative()) {
    return InvalidArgumentError(
        "PedersenOverZn::Verify(): randomness in the opening is negative.");
  }

  std::vector<BigNum> exponents = messages;
  // Add dummy 0s if fewer messages were provided.
  while (exponents.size() < gs_.size()) {
    exponents.push_back(ctx_->Zero());
  }
  // Push back the exponent for h_.
  exponents.push_back(opening);
  ASSIGN_OR_RETURN(BigNum product,
                   simultaneous_fixed_bases_exp_->SimultaneousExp(exponents));

  return commitment == product;
}

PedersenOverZn::Parameters PedersenOverZn::GenerateParameters(Context* ctx,
                                                              const BigNum& n,
                                                              int64_t num_gs) {
  // Chooses a random quadratic residue as h = (x^2) mod n for random x. Except
  // with probability O(1/n), this is a generator for the subgroup of order
  // (p-1)(q-1)/4 in Z*n.
  BigNum x = ctx->RelativelyPrimeRandomLessThan(n);
  BigNum h = x.ModSqr(n);

  std::vector<BigNum> gs;
  std::vector<BigNum> rs;
  for (int i = 0; i < num_gs; i++) {
    BigNum r =
        ctx->GenerateRandLessThan(n.DivAndTruncate(ctx->CreateBigNum(4)));
    gs.push_back(h.ModExp(r, n));
    rs.push_back(std::move(r));
  }
  return {std::move(gs), std::move(h), n, std::move(rs)};
}

std::vector<uint8_t> PedersenOverZn::GetGenProofChallenge(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const std::vector<std::unique_ptr<BigNum>>& dummy_gs, int num_repetitions) {
  std::string bytes;
  bytes.append(g.ToBytes());
  bytes.append(h.ToBytes());
  bytes.append(n.ToBytes());
  for (auto& dummy_g : dummy_gs) {
    bytes.append(dummy_g->ToBytes());
  }

  // Generates a single combined challenge, and then derive the individual
  // challenges by breaking down the combined challenge into its individual
  // bits.
  BigNum combined_challenge =
      ctx->RandomOracleSha512(bytes, ctx->One().Lshift(num_repetitions));

  std::vector<uint8_t> challenges;
  for (int i = 0; i < num_repetitions; i++) {
    uint8_t challenge = combined_challenge.IsBitSet(0);
    challenges.push_back(challenge);
    combined_challenge = combined_challenge.Rshift(1);
  }

  return challenges;
}

StatusOr<PedersenOverZn::ProofOfGen>
PedersenOverZn::ProveParametersCorrectlyGenerated(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const BigNum& r, int num_repetitions, int zk_quality) {
  if (num_repetitions <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGenerated :: number of "
        "repetitions "
        "must be positive.");
  }
  if (zk_quality <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGenerated :: zk_quality "
        "parameter "
        "must be positive.");
  }
  if (h.Gcd(n) != ctx->One()) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGenerated :: parameters are "
        "not "
        "valid: h is not relatively prime to n.");
  }
  if (g != h.ModExp(r, n)) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGenerated :: parameters are "
        "not "
        "valid: g != h^r mod n.");
  }

  // Generate first prover message for each repetition of the sigma protocol.
  std::vector<std::unique_ptr<BigNum>> dummy_rs;
  std::vector<std::unique_ptr<BigNum>> dummy_gs;
  for (int i = 0; i < num_repetitions; i++) {
    std::unique_ptr<BigNum> dummy_r(
        new BigNum(ctx->GenerateRandLessThan(n.Lshift(1 + zk_quality))));
    std::unique_ptr<BigNum> dummy_g(new BigNum(h.ModExp(*dummy_r, n)));

    dummy_rs.push_back(std::move(dummy_r));
    dummy_gs.push_back(std::move(dummy_g));
  }

  // Generate boolean challenges for each repetition of the sigma protocol
  std::vector<uint8_t> challenges =
      GetGenProofChallenge(ctx, g, h, n, dummy_gs, num_repetitions);

  // Generate responses for each proof repetition. If the challenge for the
  // repetition was "1", the response is dummy_r + r, otherwise, it is simply
  // dummy_r.
  std::vector<std::unique_ptr<BigNum>> responses;
  for (int i = 0; i < num_repetitions; i++) {
    std::unique_ptr<BigNum> response;
    if (challenges[i] == 1) {
      response = std::make_unique<BigNum>(dummy_rs[i]->Add(r));
    } else {
      response = std::make_unique<BigNum>(*dummy_rs[i]);
    }

    responses.push_back(std::move(response));
  }

  return PedersenOverZn::ProofOfGen{num_repetitions, std::move(dummy_gs),
                                    std::move(responses)};
}

Status PedersenOverZn::VerifyParamsProof(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const PedersenOverZn::ProofOfGen& proof) {
  if (proof.num_repetitions <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProof :: proof is not valid: number of "
        "repetitions must be positive.");
  }
  if (proof.dummy_gs.size() != proof.num_repetitions) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProof :: proof is not valid: number of "
        "dummy_gs is different from number of repetitions specified.");
  }
  if (proof.responses.size() != proof.num_repetitions) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProof :: proof is not valid: number of "
        "responses is different from number of repetitions specified.");
  }
  if (h.Gcd(n) != ctx->One()) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProof :: parameters are not valid, h is "
        "not "
        "relatively prime to n.");
  }

  // reconstruct the challenges
  std::vector<uint8_t> challenges = PedersenOverZn::GetGenProofChallenge(
      ctx, g, h, n, proof.dummy_gs, proof.num_repetitions);

  // checks each response to make sure it is valid for the challenge.
  for (int i = 0; i < proof.num_repetitions; i++) {
    BigNum expected_output = *proof.dummy_gs[i];
    if (challenges[i] == 1) {
      expected_output = expected_output.ModMul(g, n);
    }
    if (h.ModExp(*(proof.responses[i]), n) != expected_output) {
      return InvalidArgumentError(absl::StrCat(
          "PedersenOverZn::VerifyParamsProof :: the proof verification formula "
          "fails at index ",
          i, "."));
    }
  }

  return OkStatus();
}

BigNum PedersenOverZn::GetTrustedGenProofChallenge(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const BigNum& dummy_g, int challenge_length) {
  std::string bytes;
  bytes.append(g.ToBytes());
  bytes.append(h.ToBytes());
  bytes.append(n.ToBytes());
  bytes.append(dummy_g.ToBytes());
  BigNum challenge =
      ctx->RandomOracleSha512(bytes, ctx->One().Lshift(challenge_length));
  return challenge;
}

StatusOr<PedersenOverZn::ProofOfGenForTrustedModulus>
PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const BigNum& r, int challenge_length, int zk_quality) {
  if (challenge_length <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus :: "
        "challenge length must be positive.");
  }
  if (zk_quality <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus :: "
        "zk_quality parameter must be positive.");
  }
  if (h.Gcd(n) != ctx->One()) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus :: "
        "parameters are not valid: h is not relatively prime to n.");
  }
  if (g != h.ModExp(r, n)) {
    return InvalidArgumentError(
        "PedersenOverZn::ProveParametersCorrectlyGeneratedForTrustedModulus :: "
        "parameters are not valid: g != h^r mod n.");
  }

  BigNum dummy_r =
      ctx->GenerateRandLessThan(n.Lshift(challenge_length + zk_quality));
  BigNum dummy_g = h.ModExp(dummy_r, n);

  BigNum challenge = PedersenOverZn::GetTrustedGenProofChallenge(
      ctx, g, h, n, dummy_g, challenge_length);

  BigNum response = dummy_r + (challenge * r);

  return {{challenge_length, std::move(dummy_g), std::move(response)}};
}

Status PedersenOverZn::VerifyParamsProofForTrustedModulus(
    Context* ctx, const BigNum& g, const BigNum& h, const BigNum& n,
    const PedersenOverZn::ProofOfGenForTrustedModulus& proof) {
  if (proof.challenge_length <= 0) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProofForTrustedModulus :: proof is not "
        "valid: "
        "challenge length must be positive.");
  }
  if (h.Gcd(n) != ctx->One()) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProofForTrustedModulus :: parameters are "
        "not "
        "valid, h is not relatively prime to n.");
  }

  BigNum challenge = PedersenOverZn::GetTrustedGenProofChallenge(
      ctx, g, h, n, proof.dummy_g, proof.challenge_length);

  // checks h^response == g^challenge * dummy_g mod n.
  if (h.ModExp(proof.response, n) !=
      g.ModExp(challenge, n).ModMul(proof.dummy_g, n)) {
    return InvalidArgumentError(
        "PedersenOverZn::VerifyParamsProofForTrustedModulus :: the proof "
        "verification formula fails.");
  }

  return OkStatus();
}

proto::PedersenParameters PedersenOverZn::ParametersToProto(
    const PedersenOverZn::Parameters& parameters) {
  proto::PedersenParameters parameters_proto;
  parameters_proto.set_n(parameters.n.ToBytes());
  *parameters_proto.mutable_gs() = BigNumVectorToProto(parameters.gs);
  parameters_proto.set_h(parameters.h.ToBytes());
  return parameters_proto;
}

StatusOr<PedersenOverZn::Parameters> PedersenOverZn::ParseParametersProto(
    Context* ctx, const proto::PedersenParameters& parameters_proto) {
  BigNum n = ctx->CreateBigNum(parameters_proto.n());
  if (n <= ctx->Zero()) {
    return absl::InvalidArgumentError(
        "PedersenOverZn::FromProto: n must be positive.");
  }
  std::vector<BigNum> gs = ::private_join_and_compute::ParseBigNumVectorProto(
      ctx, parameters_proto.gs());
  for (const BigNum& g : gs) {
    if (g <= ctx->Zero() || g >= n || g.Gcd(n) != ctx->One()) {
      return absl::InvalidArgumentError(
          "PedersenOverZn::FromProto: g must be in (0, n) and relatively prime "
          "to n.");
    }
  }
  BigNum h = ctx->CreateBigNum(parameters_proto.h());
  if (h <= ctx->Zero() || h >= n || h.Gcd(n) != ctx->One()) {
    return absl::InvalidArgumentError(
        "PedersenOverZn::FromProto: h must be in (0, n) and relatively prime "
        "to n.");
  }
  return PedersenOverZn::Parameters{
      std::move(gs), std::move(h), std::move(n), {}};
}

}  // namespace private_join_and_compute
