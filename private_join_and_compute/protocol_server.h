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

#ifndef PRIVATE_JOIN_AND_COMPUTE_PROTOCOL_SERVER_H_
#define PRIVATE_JOIN_AND_COMPUTE_PROTOCOL_SERVER_H_

#include "private_join_and_compute/message_sink.h"
#include "private_join_and_compute/private_join_and_compute.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// Abstract class representing a server for a cryptographic protocol.
//
// In all subclasses, the server should expect the first protocol message to be
// sent by the client. (If the protocol requires the server to send the first
// meaningful message, the first client message can be a dummy.)
class ProtocolServer {
 public:
  virtual ~ProtocolServer() = default;

  // All subclasses should check that the client_message is the right type, and,
  // if so, execute the next round of the server, which may involve sending one
  // or more messages to the server message sink.
  virtual Status Handle(const ClientMessage& client_message,
                        MessageSink<ServerMessage>* server_message_sink) = 0;

  // All subclasses should return true if the protocol is complete, and false
  // otherwise.
  virtual bool protocol_finished() = 0;

 protected:
  ProtocolServer() = default;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_PROTOCOL_SERVER_H_
