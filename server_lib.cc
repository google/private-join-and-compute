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

#include "server_lib.h"

#include <algorithm>

#include "crypto/paillier.h"
#include "crypto/ec_commutative_cipher.h"
#include "absl/memory/memory.h"

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::Context;
using ::private_join_and_compute::ECCommutativeCipher;
using ::private_join_and_compute::PublicPaillier;
using ::util::StatusOr;

namespace private_join_and_compute {

Server::Server(Context* ctx, const std::vector<std::string>& inputs)
    : ctx_(ctx), inputs_(inputs) {}

Server::Server(Context* ctx, const std::string& serialized_state) : ctx_(ctx) {
  ServerState state;
  CHECK(state.ParseFromString(serialized_state));
  if (state.has_ec_key()) {
    ec_cipher_ = std::move(
        ECCommutativeCipher::CreateFromKey(NID_secp224r1, state.ec_key())
            .ValueOrDie());
  }
}

StatusOr<ServerRoundOne> Server::EncryptSet() {
  if (ec_cipher_ != nullptr) {
    return util::InvalidArgumentError("Attempted to call EncryptSet twice.");
  }
  StatusOr<std::unique_ptr<ECCommutativeCipher>> ec_cipher =
      ECCommutativeCipher::CreateWithNewKey(NID_secp224r1);
  if (!ec_cipher.ok()) {
    return ec_cipher.status();
  }
  ec_cipher_ = std::move(ec_cipher.ValueOrDie());

  ServerRoundOne result;
  for (const std::string& input : inputs_) {
    EncryptedElement* encrypted =
        result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted_element = ec_cipher_->Encrypt(input);
    if (!encrypted_element.ok()) {
      return encrypted_element.status();
    }
    *encrypted->mutable_element() = encrypted_element.ValueOrDie();
  }

  return result;
}

StatusOr<ServerRoundTwo> Server::ComputeIntersection(
    const ClientRoundOne& client_message) {
  if (ec_cipher_ == nullptr) {
    return util::InvalidArgumentError(
        "Called ComputeIntersection before EncryptSet.");
  }
  ServerRoundTwo result;
  BigNum N = ctx_->CreateBigNum(client_message.public_key());
  PublicPaillier public_paillier(ctx_, N, 2);

  std::vector<EncryptedElement> server_set, client_set, intersection;

  // First, we re-encrypt the client party's set, so that we can compare with
  // the re-encrypted set received from the client.
  for (const EncryptedElement& element :
       client_message.encrypted_set().elements()) {
    EncryptedElement reencrypted;
    *reencrypted.mutable_associated_data() = element.associated_data();
    StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
    if (!reenc.ok()) {
      return reenc.status();
    }
    *reencrypted.mutable_element() = reenc.ValueOrDie();
    client_set.push_back(reencrypted);
  }
  for (const EncryptedElement& element :
       client_message.reencrypted_set().elements()) {
    server_set.push_back(element);
  }

  // std::set_intersection requires sorted inputs.
  std::sort(client_set.begin(), client_set.end(),
            [](const EncryptedElement& a, const EncryptedElement& b) {
              return a.element() < b.element();
            });
  std::sort(server_set.begin(), server_set.end(),
            [](const EncryptedElement& a, const EncryptedElement& b) {
              return a.element() < b.element();
            });
  std::set_intersection(
      client_set.begin(), client_set.end(), server_set.begin(),
      server_set.end(), std::back_inserter(intersection),
      [](const EncryptedElement& a, const EncryptedElement& b) {
        return a.element() < b.element();
      });

  // From the intersection we compute the sum of the associated values, which is
  // the result we return to the client.
  StatusOr<BigNum> encrypted_zero =
      public_paillier.Encrypt(ctx_->CreateBigNum(0));
  if (!encrypted_zero.ok()) {
    return encrypted_zero.status();
  }
  BigNum sum = encrypted_zero.ValueOrDie();
  for (const EncryptedElement& element : intersection) {
    sum =
        public_paillier.Add(sum, ctx_->CreateBigNum(element.associated_data()));
  }

  *result.mutable_encrypted_sum() = sum.ToBytes();
  result.set_intersection_size(intersection.size());
  return result;
}

std::string Server::GetSerializedState() const {
  ServerState state;
  if (ec_cipher_ != nullptr) {
    *state.mutable_ec_key() = ec_cipher_->GetPrivateKeyBytes();
  }
  return state.SerializeAsString();
}

}  // namespace private_join_and_compute
