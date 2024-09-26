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

#include "private_join_and_compute/server_impl.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"
#include "private_join_and_compute/util/status.inc"

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::ECCommutativeCipher;

namespace private_join_and_compute {

StatusOr<PrivateIntersectionSumServerMessage::ServerRoundOne>
PrivateIntersectionSumProtocolServerImpl::EncryptSet() {
  if (ec_cipher_ != nullptr) {
    return InvalidArgumentError("Attempted to call EncryptSet twice.");
  }
  StatusOr<std::unique_ptr<ECCommutativeCipher>> ec_cipher =
      ECCommutativeCipher::CreateWithNewKey(
          NID_X9_62_prime256v1, ECCommutativeCipher::HashType::SHA256);
  if (!ec_cipher.ok()) {
    return ec_cipher.status();
  }
  ec_cipher_ = std::move(ec_cipher.value());

  PrivateIntersectionSumServerMessage::ServerRoundOne result;
  for (const std::string& input : inputs_) {
    EncryptedElement* encrypted =
        result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted_element = ec_cipher_->Encrypt(input);
    if (!encrypted_element.ok()) {
      return encrypted_element.status();
    }
    *encrypted->mutable_element() = encrypted_element.value();
  }

  return result;
}

StatusOr<PrivateIntersectionSumServerMessage::ServerRoundTwo>
PrivateIntersectionSumProtocolServerImpl::ComputeIntersection(
    const PrivateIntersectionSumClientMessage::ClientRoundOne& client_message) {
  if (ec_cipher_ == nullptr) {
    return InvalidArgumentError(
        "Called ComputeIntersection before EncryptSet.");
  }
  PrivateIntersectionSumServerMessage::ServerRoundTwo result;
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
    *reencrypted.mutable_element() = reenc.value();
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
  BigNum sum = encrypted_zero.value();
  for (const EncryptedElement& element : intersection) {
    sum =
        public_paillier.Add(sum, ctx_->CreateBigNum(element.associated_data()));
  }

  *result.mutable_encrypted_sum() = sum.ToBytes();
  result.set_intersection_size(intersection.size());
  return result;
}

Status PrivateIntersectionSumProtocolServerImpl::Handle(
    const ClientMessage& request,
    MessageSink<ServerMessage>* server_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Protocol is already "
        "complete.");
  }

  // Check that the message is a PrivateIntersectionSum protocol message.
  if (!request.has_private_intersection_sum_client_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Received a message for the "
        "wrong protocol type");
  }
  const PrivateIntersectionSumClientMessage& client_message =
      request.private_intersection_sum_client_message();

  ServerMessage server_message;

  if (client_message.has_start_protocol_request()) {
    // Handle a protocol start message.
    auto maybe_server_round_one = EncryptSet();
    if (!maybe_server_round_one.ok()) {
      return maybe_server_round_one.status();
    }
    *(server_message.mutable_private_intersection_sum_server_message()
          ->mutable_server_round_one()) =
        std::move(maybe_server_round_one.value());
  } else if (client_message.has_client_round_one()) {
    // Handle the client round 1 message.
    auto maybe_server_round_two =
        ComputeIntersection(client_message.client_round_one());
    if (!maybe_server_round_two.ok()) {
      return maybe_server_round_two.status();
    }
    *(server_message.mutable_private_intersection_sum_server_message()
          ->mutable_server_round_two()) =
        std::move(maybe_server_round_two.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
  } else {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Received a client message "
        "of an unknown type.");
  }

  return server_message_sink->Send(server_message);
}

}  // namespace private_join_and_compute
