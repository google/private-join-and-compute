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

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/client_context.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/status.h"
#include "private_join_and_compute/client_impl.h"
#include "private_join_and_compute/data_util.h"
#include "private_join_and_compute/private_join_and_compute.grpc.pb.h"
#include "private_join_and_compute/private_join_and_compute.pb.h"
#include "private_join_and_compute/protocol_client.h"
#include "private_join_and_compute/util/status.inc"

ABSL_FLAG(std::string, port, "0.0.0.0:10501",
          "Port on which to contact server");
ABSL_FLAG(std::string, client_data_file, "",
          "The file from which to read the client database.");
ABSL_FLAG(
    int32_t, paillier_modulus_size, 1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size "
    "paillier_modulus_size/2.");

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

int ExecuteProtocol() {
  ::private_join_and_compute::Context context;

  std::cout << "Client: Loading data..." << std::endl;
  auto maybe_client_identifiers_and_associated_values =
      ::private_join_and_compute::ReadClientDatasetFromFile(
          absl::GetFlag(FLAGS_client_data_file), &context);
  if (!maybe_client_identifiers_and_associated_values.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed "
              << maybe_client_identifiers_and_associated_values.status()
              << std::endl;
    return 1;
  }
  auto client_identifiers_and_associated_values =
      std::move(maybe_client_identifiers_and_associated_values.value());

  std::cout << "Client: Generating keys..." << std::endl;
  std::unique_ptr<::private_join_and_compute::ProtocolClient> client =
      std::make_unique<
          ::private_join_and_compute::PrivateIntersectionSumProtocolClientImpl>(
          &context, std::move(client_identifiers_and_associated_values.first),
          std::move(client_identifiers_and_associated_values.second),
          absl::GetFlag(FLAGS_paillier_modulus_size));

  // Consider grpc::SslServerCredentials if not running locally.
  std::unique_ptr<PrivateJoinAndComputeRpc::Stub> stub =
      PrivateJoinAndComputeRpc::NewStub(::grpc::CreateChannel(
          absl::GetFlag(FLAGS_port), ::grpc::experimental::LocalCredentials(
                                         grpc_local_connect_type::LOCAL_TCP)));
  InvokeServerHandleClientMessageSink invoke_server_handle_message_sink(
      std::move(stub));

  // Execute StartProtocol and wait for response from ServerRoundOne.
  std::cout
      << "Client: Starting the protocol." << std::endl
      << "Client: Waiting for response and encrypted set from the server..."
      << std::endl;
  auto start_protocol_status =
      client->StartProtocol(&invoke_server_handle_message_sink);
  if (!start_protocol_status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to StartProtocol: "
              << start_protocol_status << std::endl;
    return 1;
  }
  ServerMessage server_round_one =
      invoke_server_handle_message_sink.last_server_response();

  // Execute ClientRoundOne, and wait for response from ServerRoundTwo.
  std::cout
      << "Client: Received encrypted set from the server, double encrypting..."
      << std::endl;
  std::cout << "Client: Sending double encrypted server data and "
               "single-encrypted client data to the server."
            << std::endl
            << "Client: Waiting for encrypted intersection sum..." << std::endl;
  auto client_round_one_status =
      client->Handle(server_round_one, &invoke_server_handle_message_sink);
  if (!client_round_one_status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to ReEncryptSet: "
              << client_round_one_status << std::endl;
    return 1;
  }

  // Execute ServerRoundTwo.
  std::cout << "Client: Sending double encrypted server data and "
               "single-encrypted client data to the server."
            << std::endl
            << "Client: Waiting for encrypted intersection sum..." << std::endl;
  ServerMessage server_round_two =
      invoke_server_handle_message_sink.last_server_response();

  // Compute the intersection size and sum.
  std::cout << "Client: Received response from the server. Decrypting the "
               "intersection-sum."
            << std::endl;
  auto intersection_size_and_sum_status =
      client->Handle(server_round_two, &invoke_server_handle_message_sink);
  if (!intersection_size_and_sum_status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to DecryptSum: "
              << intersection_size_and_sum_status << std::endl;
    return 1;
  }

  // Output the result.
  auto client_print_output_status = client->PrintOutput();
  if (!client_print_output_status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to PrintOutput: "
              << client_print_output_status << std::endl;
    return 1;
  }

  return 0;
}

}  // namespace
}  // namespace private_join_and_compute

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  return private_join_and_compute::ExecuteProtocol();
}
