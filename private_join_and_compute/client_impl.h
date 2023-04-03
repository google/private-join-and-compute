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

#ifndef PRIVATE_JOIN_AND_COMPUTE_PRIVATE_INTERSECTION_SUM_CLIENT_IMPL_H_
#define PRIVATE_JOIN_AND_COMPUTE_PRIVATE_INTERSECTION_SUM_CLIENT_IMPL_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"
#include "private_join_and_compute/match.pb.h"
#include "private_join_and_compute/message_sink.h"
#include "private_join_and_compute/private_intersection_sum.pb.h"
#include "private_join_and_compute/private_join_and_compute.pb.h"
#include "private_join_and_compute/protocol_client.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// This class represents the "client" part of the intersection-sum protocol,
// which supplies the associated values that will be used to compute the sum.
// This is the party that will receive the sum as output.
class PrivateIntersectionSumProtocolClientImpl : public ProtocolClient {
 public:
  PrivateIntersectionSumProtocolClientImpl(
      Context* ctx, const std::vector<std::string>& elements,
      const std::vector<BigNum>& values, int32_t modulus_size);

  // Generates the StartProtocol message and sends it on the message sink.
  Status StartProtocol(
      MessageSink<ClientMessage>* client_message_sink) override;

  // Executes the next Client round and creates a new server request, which must
  // be sent to the server unless the protocol is finished.
  //
  // If the ServerMessage is ServerRoundOne, a ClientRoundOne will be sent on
  // the message sink, containing the encrypted client identifiers and
  // associated values, and the re-encrypted and shuffled server identifiers.
  //
  // If the ServerMessage is ServerRoundTwo, nothing will be sent on
  // the message sink, and the client will internally store the intersection sum
  // and size. The intersection sum and size can be retrieved either through
  // accessors, or by calling PrintOutput.
  //
  // Fails with InvalidArgument if the message is not a
  // PrivateIntersectionSumServerMessage of the expected round, or if the
  // message is otherwise not as expected. Forwards all other failures
  // encountered.
  Status Handle(const ServerMessage& server_message,
                MessageSink<ClientMessage>* client_message_sink) override;

  // Prints the result, namely the intersection size and the intersection sum.
  Status PrintOutput() override;

  bool protocol_finished() override { return protocol_finished_; }

  // Utility functions for testing.
  int64_t intersection_size() const { return intersection_size_; }
  const BigNum& intersection_sum() const { return intersection_sum_; }

 private:
  // The server sends the first message of the protocol, which contains its
  // encrypted set.  This party then re-encrypts that set and replies with the
  // reencrypted values and its own encrypted set.
  StatusOr<PrivateIntersectionSumClientMessage::ClientRoundOne> ReEncryptSet(
      const PrivateIntersectionSumServerMessage::ServerRoundOne&
          server_message);

  // After the server computes the intersection-sum, it will send it back to
  // this party for decryption, together with the intersection_size. This party
  // will decrypt and output the intersection sum and intersection size.
  StatusOr<std::pair<int64_t, BigNum>> DecryptSum(
      const PrivateIntersectionSumServerMessage::ServerRoundTwo&
          server_message);

  Context* ctx_;  // not owned
  std::vector<std::string> elements_;
  std::vector<BigNum> values_;

  // The Paillier private key
  BigNum p_, q_;

  // These values will hold the intersection sum and size when the protocol has
  // been completed.
  int64_t intersection_size_ = 0;
  BigNum intersection_sum_;

  std::unique_ptr<ECCommutativeCipher> ec_cipher_;
  std::unique_ptr<PrivatePaillier> private_paillier_;

  bool protocol_finished_ = false;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_PRIVATE_INTERSECTION_SUM_CLIENT_IMPL_H_
