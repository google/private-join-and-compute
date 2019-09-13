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

#include "private_join_and_compute.h"

#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/client_context.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"

#include "client_impl.h"
#include "server_impl.h"
#include "private_join_and_compute.grpc.pb.h"
#include "private_join_and_compute_rpc_impl.h"
#include "private_join_and_compute.pb.h"
#include "protocol_client.h"
#include "protocol_server.h"

#include "util/status.inc"

namespace private_join_and_compute {

namespace {

class InvokeServerHandleClientMessageSink : public MessageSink<ClientMessage> {
 public:
  explicit InvokeServerHandleClientMessageSink(
      std::unique_ptr<PrivateJoinAndComputeRpc::Stub> stub)
      : stub_(std::move(stub)) {}

  ~InvokeServerHandleClientMessageSink() override = default;

  Status Send(const ClientMessage& message) override {
    ::grpc::ClientContext client_context;
    ::grpc::Status grpc_status =
        stub_->Handle(&client_context, message, &last_server_response_);
    if (grpc_status.ok()) {
      return OkStatus();
    } else {
      return InternalError(absl::StrCat(
          "GrpcClientMessageSink: Failed to send message, error code: ",
          grpc_status.error_code(),
          ", error_message: ", grpc_status.error_message()));
    }
  }

  const ServerMessage& last_server_response() { return last_server_response_; }

 private:
  std::unique_ptr<PrivateJoinAndComputeRpc::Stub> stub_;
  ServerMessage last_server_response_;
};

}  // namespace

ClientSession::ClientSession() = default;

ClientSession::~ClientSession() = default;

int ClientSession::Run(
    int32_t paillier_modulus_size,
    std::string port,
    const std::vector<std::string>& elements,
    const std::vector<int64_t>& values,
    ClientResult* result) {

  Context context;

  // convert values to BigNums
  std::vector<BigNum> values_as_bignum;
  for (auto const& value: values) {
    values_as_bignum.push_back(context.CreateBigNum(value));
  }

  // set up protocol client
  std::unique_ptr<ProtocolClient> client =
      absl::make_unique<PrivateIntersectionSumProtocolClientImpl>(
          &context,
          elements,
          values_as_bignum,
          paillier_modulus_size);

  // set up gRPC channel
  // TODO(Morten) use grpc::SslServerCredentials
  auto credentials = ::grpc::experimental::LocalCredentials(grpc_local_connect_type::LOCAL_TCP);
  auto channel = ::grpc::CreateChannel(port, credentials);
  std::unique_ptr<PrivateJoinAndComputeRpc::Stub> stub = PrivateJoinAndComputeRpc::NewStub(channel);
  InvokeServerHandleClientMessageSink message_sink(std::move(stub));

  // Execute StartProtocol and wait for response from ServerRoundOne.
  auto start_protocol_status = client->StartProtocol(&message_sink);
  if (!start_protocol_status.ok()) {
    return 1;
  }
  ServerMessage server_round_one = message_sink.last_server_response();

  // Execute ClientRoundOne, and wait for response from ServerRoundTwo.
  auto client_round_one_status = client->Handle(server_round_one, &message_sink);
  if (!client_round_one_status.ok()) {
    return 1;
  }
  ServerMessage server_round_two = message_sink.last_server_response();

  // Compute the intersection size and sum.
  auto intersection_size_and_sum_status = client->Handle(server_round_two, &message_sink);
  if (!intersection_size_and_sum_status.ok()) {
    return 1;
  }

  // Output the result.
  auto maybe_client_result = client->ReturnOutput();
  if (!maybe_client_result.ok()) {
    return 1;
  }

  std::tie(result->intersection_size, result->intersection_sum) = maybe_client_result.ValueOrDie();

  return 0;
}

class ServerSession::ServerSessionState {
  public:
    
    ServerSessionState() : 
        context(std::make_shared<Context>()),
        finished(std::make_shared<absl::Notification>()) {}

    std::shared_ptr<Context> context;
    std::shared_ptr<absl::Notification> finished;
    std::unique_ptr<PrivateJoinAndComputeRpcImpl> service;
    std::unique_ptr<grpc::Server> grpc_server;
};

ServerSession::ServerSession() :
    _state(absl::make_unique<ServerSessionState>()) {}

ServerSession::~ServerSession() = default;

int ServerSession::Run(
    std::string port,
    const std::vector<std::string>& elements) {    
  int res;

  res = RunAsync(port, elements);
  if (0 != res) {
    return res;
  }

  res = Wait();
  return res;
}

int ServerSession::RunAsync(
    std::string port,
    const std::vector<std::string>& elements) {

  std::unique_ptr<ProtocolServer> server = absl::make_unique<PrivateIntersectionSumProtocolServerImpl>(
      _state->context.get(),
      _state->finished.get(),
      std::move(elements));

  // we need to hang on to this since the gRPC server will not take ownership
  _state->service = absl::make_unique<PrivateJoinAndComputeRpcImpl>(std::move(server));

  ::grpc::ServerBuilder builder;
  // TODO grpc::SslServerCredentials
  auto credentials = ::grpc::experimental::LocalServerCredentials(grpc_local_connect_type::LOCAL_TCP);
  builder.AddListeningPort(port, credentials);
  builder.RegisterService(_state->service.get());  
  _state->grpc_server = builder.BuildAndStart();

  return 0;
}

int ServerSession::Wait() {
  while (!_state->finished->HasBeenNotified()) {
    _state->finished->WaitForNotificationWithTimeout(absl::Milliseconds(100));
  }
  _state->grpc_server->Shutdown();
  return 0;
}

}  // namespace private_join_and_compute
