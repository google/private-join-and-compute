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

#ifndef OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_
#define OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_

#include "glog/logging.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "match.grpc.pb.h"
#include "match.pb.h"
#include "server_lib.h"

namespace private_join_and_compute {

// Implements the PrivateJoin and Compute RPC-handling Server.
class PrivateJoinAndComputeRpcImpl : public PrivateJoinAndComputeRpc::Service {
 public:
  explicit PrivateJoinAndComputeRpcImpl(std::unique_ptr<Server> server)
      : server_(std::move(server)), protocol_finished_(false) {}

  // Starts the protocol, triggering an encrypted first message from the server.
  ::grpc::Status StartProtocol(::grpc::ServerContext* context,
                               const StartProtocolRequest* request,
                               ServerRoundOne* response) override;

  // Executes the second round of the protocol, and marks the protocol as
  // finished if the step succeeded.
  ::grpc::Status ExecuteServerRoundTwo(::grpc::ServerContext* context,
                                       const ClientRoundOne* request,
                                       ServerRoundTwo* response) override;

  bool protocol_finished() const { return protocol_finished_; }

 private:
  std::unique_ptr<Server> server_;
  bool protocol_finished_;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_
