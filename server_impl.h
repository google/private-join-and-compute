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

#ifndef OPEN_SOURCE_SERVER_IMPL_H_
#define OPEN_SOURCE_SERVER_IMPL_H_

#include "absl/synchronization/notification.h"

#include "crypto/context.h"
#include "crypto/paillier.h"
#include "match.pb.h"
#include "message_sink.h"
#include "private_intersection_sum.pb.h"
#include "private_join_and_compute.pb.h"
#include "protocol_server.h"
#include "util/status.inc"
#include "crypto/ec_commutative_cipher.h"

namespace private_join_and_compute {

// The "server side" of the intersection-sum protocol.  This represents the
// party that will receive the size of the intersection as its output.  The
// values that will be summed are supplied by the other party; this party will
// only supply set elements as its inputs.
class PrivateIntersectionSumProtocolServerImpl : public ProtocolServer {
 public:
  PrivateIntersectionSumProtocolServerImpl(::private_join_and_compute::Context* ctx,
                                           absl::Notification* protocol_finished_notification,
                                           std::vector<std::string> inputs)
      : ctx_(ctx),
        protocol_finished_notification_(protocol_finished_notification),
        inputs_(std::move(inputs)) {}

  ~PrivateIntersectionSumProtocolServerImpl() override = default;

  // Executes the next Server round and creates a response.
  //
  // If the ClientMessage is StartProtocol, a ServerRoundOne will be sent to the
  // message sink, containing the encrypted server identifiers.
  //
  // If the ClientMessage is ClientRoundOne, a ServerRoundTwo will be sent to
  // the message sink, containing the intersection size, and encrypted
  // intersection-sum.
  //
  // Fails with InvalidArgument if the message is not a
  // PrivateIntersectionSumClientMessage of the expected round, or if the
  // message is otherwise not as expected. Forwards all other failures
  // encountered.
  Status Handle(const ClientMessage& request,
                MessageSink<ServerMessage>* server_message_sink) override;

  bool protocol_finished() override { return protocol_finished_; }

  // Utility function, used for testing.
  ECCommutativeCipher* GetECCipher() { return ec_cipher_.get(); }

 private:
  // Encrypts the server's identifiers.
  StatusOr<PrivateIntersectionSumServerMessage::ServerRoundOne> EncryptSet();

  // Computes the intersection size and encrypted intersection_sum.
  StatusOr<PrivateIntersectionSumServerMessage::ServerRoundTwo>
  ComputeIntersection(const PrivateIntersectionSumClientMessage::ClientRoundOne&
                          client_message);

  Context* ctx_;  // not owned
  absl::Notification* protocol_finished_notification_;  // not owned
  std::unique_ptr<ECCommutativeCipher> ec_cipher_;

  // inputs_ will first contain the plaintext server identifiers, and later
  // contain the encrypted server identifiers.
  std::vector<std::string> inputs_;
  bool protocol_finished_ = false;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_SERVER_IMPL_H_
