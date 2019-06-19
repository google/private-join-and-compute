/*
 * Copyright 2019 Google Inc.
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

#include "client_lib.h"

#include <algorithm>
#include <iterator>

#include "absl/memory/memory.h"

namespace private_join_and_compute {

using ::util::StatusOr;

Client::Client(Context* ctx, const std::vector<std::string>& elements,
               const std::vector<BigNum>& values, int32_t modulus_size)
    : ctx_(ctx),
      elements_(elements),
      values_(values),
      p_(ctx_->GenerateSafePrime(modulus_size / 2)),
      q_(ctx_->GenerateSafePrime(modulus_size / 2)),
      ec_cipher_(std::move(
          ECCommutativeCipher::CreateWithNewKey(NID_secp224r1).ValueOrDie())) {}

Client::Client(Context* ctx, const std::string& serialized)
    : ctx_(ctx), p_(ctx_->CreateBigNum(0)), q_(ctx_->CreateBigNum(0)) {
  ClientState state;
  assert(state.ParseFromString(serialized));
  if (state.has_p() && state.has_q()) {
    p_ = ctx_->CreateBigNum(state.p());
    q_ = ctx_->CreateBigNum(state.q());
    private_paillier_ = absl::make_unique<PrivatePaillier>(ctx_, p_, q_, 2);
  }
  ec_cipher_ = std::move(
      ECCommutativeCipher::CreateFromKey(NID_secp224r1, state.ec_key())
          .ValueOrDie());
}

StatusOr<ClientRoundOne> Client::ReEncryptSet(const ServerRoundOne& message) {
  private_paillier_ = absl::make_unique<PrivatePaillier>(ctx_, p_, q_, 2);
  BigNum pk = p_ * q_;
  ClientRoundOne result;
  *result.mutable_public_key() = pk.ToBytes();
  for (size_t i = 0; i < elements_.size(); i++) {
    EncryptedElement* element = result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted = ec_cipher_->Encrypt(elements_[i]);
    if (!encrypted.ok()) {
      return encrypted.status();
    }
    *element->mutable_element() = encrypted.ValueOrDie();
    StatusOr<BigNum> value = private_paillier_->Encrypt(values_[i]);
    if (!value.ok()) {
      return value.status();
    }
    *element->mutable_associated_data() = value.ValueOrDie().ToBytes();
  }

  std::vector<EncryptedElement> reencrypted_set;
  for (const EncryptedElement& element : message.encrypted_set().elements()) {
    EncryptedElement reencrypted;
    StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
    if (!reenc.ok()) {
      return reenc.status();
    }
    *reencrypted.mutable_element() = reenc.ValueOrDie();
    reencrypted_set.push_back(reencrypted);
  }
  std::sort(reencrypted_set.begin(), reencrypted_set.end(),
            [](const EncryptedElement& a, const EncryptedElement& b) {
              return a.element() < b.element();
            });
  for (const EncryptedElement& element : reencrypted_set) {
    *result.mutable_reencrypted_set()->add_elements() = element;
  }

  return result;
}

StatusOr<std::pair<int64_t, BigNum>> Client::DecryptSum(
    const ServerRoundTwo& server_message) {
  if (private_paillier_ == nullptr) {
    return util::InvalidArgumentError("Called DecryptSum before ReEncryptSet.");
  }

  StatusOr<BigNum> sum = private_paillier_->Decrypt(
      ctx_->CreateBigNum(server_message.encrypted_sum()));
  if (!sum.ok()) {
    return sum.status();
  }
  return std::make_pair(server_message.intersection_size(), sum.ValueOrDie());
}

std::string Client::GetSerializedState() const {
  ClientState state;
  *state.mutable_p() = p_.ToBytes();
  *state.mutable_q() = q_.ToBytes();
  *state.mutable_ec_key() = ec_cipher_->GetPrivateKeyBytes();
  return state.SerializeAsString();
}

}  // namespace private_join_and_compute
