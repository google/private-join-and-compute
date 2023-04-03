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

#include "private_join_and_compute/client_impl.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"

namespace private_join_and_compute {

PrivateIntersectionSumProtocolClientImpl::
    PrivateIntersectionSumProtocolClientImpl(
        Context* ctx, const std::vector<std::string>& elements,
        const std::vector<BigNum>& values, int32_t modulus_size)
    : ctx_(ctx),
      elements_(elements),
      values_(values),
      p_(ctx_->GenerateSafePrime(modulus_size / 2)),
      q_(ctx_->GenerateSafePrime(modulus_size / 2)),
      intersection_sum_(ctx->Zero()),
      ec_cipher_(std::move(
          ECCommutativeCipher::CreateWithNewKey(
              NID_X9_62_prime256v1, ECCommutativeCipher::HashType::SHA256)
              .value())) {}

StatusOr<PrivateIntersectionSumClientMessage::ClientRoundOne>
PrivateIntersectionSumProtocolClientImpl::ReEncryptSet(
    const PrivateIntersectionSumServerMessage::ServerRoundOne& message) {
  private_paillier_ = std::make_unique<PrivatePaillier>(ctx_, p_, q_, 2);
  BigNum pk = p_ * q_;
  PrivateIntersectionSumClientMessage::ClientRoundOne result;
  *result.mutable_public_key() = pk.ToBytes();
  for (size_t i = 0; i < elements_.size(); i++) {
    EncryptedElement* element = result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted = ec_cipher_->Encrypt(elements_[i]);
    if (!encrypted.ok()) {
      return encrypted.status();
    }
    *element->mutable_element() = encrypted.value();
    StatusOr<BigNum> value = private_paillier_->Encrypt(values_[i]);
    if (!value.ok()) {
      return value.status();
    }
    *element->mutable_associated_data() = value.value().ToBytes();
  }

  std::vector<EncryptedElement> reencrypted_set;
  for (const EncryptedElement& element : message.encrypted_set().elements()) {
    EncryptedElement reencrypted;
    StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
    if (!reenc.ok()) {
      return reenc.status();
    }
    *reencrypted.mutable_element() = reenc.value();
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

StatusOr<std::pair<int64_t, BigNum>>
PrivateIntersectionSumProtocolClientImpl::DecryptSum(
    const PrivateIntersectionSumServerMessage::ServerRoundTwo& server_message) {
  if (private_paillier_ == nullptr) {
    return InvalidArgumentError("Called DecryptSum before ReEncryptSet.");
  }

  StatusOr<BigNum> sum = private_paillier_->Decrypt(
      ctx_->CreateBigNum(server_message.encrypted_sum()));
  if (!sum.ok()) {
    return sum.status();
  }
  return std::make_pair(server_message.intersection_size(), sum.value());
}

Status PrivateIntersectionSumProtocolClientImpl::StartProtocol(
    MessageSink<ClientMessage>* client_message_sink) {
  ClientMessage client_message;
  *(client_message.mutable_private_intersection_sum_client_message()
        ->mutable_start_protocol_request()) =
      PrivateIntersectionSumClientMessage::StartProtocolRequest();
  return client_message_sink->Send(client_message);
}

Status PrivateIntersectionSumProtocolClientImpl::Handle(
    const ServerMessage& server_message,
    MessageSink<ClientMessage>* client_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Protocol is already "
        "complete.");
  }

  // Check that the message is a PrivateIntersectionSum protocol message.
  if (!server_message.has_private_intersection_sum_server_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Received a message for the "
        "wrong protocol type");
  }

  if (server_message.private_intersection_sum_server_message()
          .has_server_round_one()) {
    // Handle the server round one message.
    ClientMessage client_message;

    auto maybe_client_round_one =
        ReEncryptSet(server_message.private_intersection_sum_server_message()
                         .server_round_one());
    if (!maybe_client_round_one.ok()) {
      return maybe_client_round_one.status();
    }
    *(client_message.mutable_private_intersection_sum_client_message()
          ->mutable_client_round_one()) =
        std::move(maybe_client_round_one.value());
    return client_message_sink->Send(client_message);
  } else if (server_message.private_intersection_sum_server_message()
                 .has_server_round_two()) {
    // Handle the server round two message.
    auto maybe_result =
        DecryptSum(server_message.private_intersection_sum_server_message()
                       .server_round_two());
    if (!maybe_result.ok()) {
      return maybe_result.status();
    }
    std::tie(intersection_size_, intersection_sum_) =
        std::move(maybe_result.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
    return OkStatus();
  }
  // If none of the previous cases matched, we received the wrong kind of
  // message.
  return InvalidArgumentError(
      "PrivateIntersectionSumProtocolClientImpl: Received a server message "
      "of an unknown type.");
}

Status PrivateIntersectionSumProtocolClientImpl::PrintOutput() {
  if (!protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Not ready to print the "
        "output yet.");
  }
  auto maybe_converted_intersection_sum = intersection_sum_.ToIntValue();
  if (!maybe_converted_intersection_sum.ok()) {
    return maybe_converted_intersection_sum.status();
  }
  std::cout << "Client: The intersection size is " << intersection_size_
            << " and the intersection-sum is "
            << maybe_converted_intersection_sum.value() << std::endl;
  return OkStatus();
}

}  // namespace private_join_and_compute
