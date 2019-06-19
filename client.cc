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

#include <iostream>
#include <memory>
#include <string>

#include "gflags/gflags.h"

#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/client_context.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/status.h"
#include "client_lib.h"
#include "data_util.h"
#include "match.grpc.pb.h"
#include "match.pb.h"
#include "absl/memory/memory.h"

DEFINE_string(port, "0.0.0.0:10501", "Port on which to contact server");
DEFINE_string(client_data_file, "",
              "The file from which to read the client database.");
DEFINE_int32(
    paillier_modulus_size, 1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size "
    "paillier_modulus_size/2.");

using ::private_join_and_compute::PrivateJoinAndComputeRpc;

int ExecuteProtocol() {
  ::private_join_and_compute::Context context;

  std::cout << "Client: Loading data..." << std::endl;
  auto maybe_client_identifiers_and_associated_values =
      ::private_join_and_compute::ReadClientDatasetFromFile(FLAGS_client_data_file, &context);
  if (!maybe_client_identifiers_and_associated_values.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed "
              << maybe_client_identifiers_and_associated_values.status()
              << std::endl;
    return 1;
  }
  auto client_identifiers_and_associated_values =
      std::move(maybe_client_identifiers_and_associated_values.ValueOrDie());

  std::cout << "Client: Generating keys..." << std::endl;
  std::unique_ptr<::private_join_and_compute::Client> client =
      absl::make_unique<::private_join_and_compute::Client>(
          &context, std::move(client_identifiers_and_associated_values.first),
          std::move(client_identifiers_and_associated_values.second),
          FLAGS_paillier_modulus_size);

  // Consider grpc::SslServerCredentials if not running locally.
  std::unique_ptr<PrivateJoinAndComputeRpc::Stub> stub =
      PrivateJoinAndComputeRpc::NewStub(::grpc::CreateChannel(
          FLAGS_port, ::grpc::experimental::LocalCredentials(
                          grpc_local_connect_type::LOCAL_TCP)));

  // Execute StartProtocol.
  std::cout
      << "Client: Starting the protocol." << std::endl
      << "Client: Waiting for response and encrypted set from the server..."
      << std::endl;
  ::private_join_and_compute::StartProtocolRequest start_protocol_request;
  ::private_join_and_compute::ServerRoundOne server_round_one;
  ::grpc::ClientContext start_protocol_client_context;
  ::grpc::Status status =
      stub->StartProtocol(&start_protocol_client_context,
                          start_protocol_request, &server_round_one);
  if (!status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to StartProtocol: "
              << status.error_message() << std::endl;
    return 1;
  }

  // Execute ClientRoundOne.
  std::cout
      << "Client: Received encrypted set from the server, double encrypting..."
      << std::endl;
  auto maybe_client_round_one = client->ReEncryptSet(server_round_one);
  if (!maybe_client_round_one.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to ReEncryptSet: "
              << maybe_client_round_one.status() << std::endl;
    return 1;
  }
  auto client_round_one = std::move(maybe_client_round_one.ValueOrDie());

  // Execute ServerRoundTwo.
  std::cout << "Client: Sending double encrypted server data and "
               "single-encrypted client data to the server."
            << std::endl
            << "Client: Waiting for encrypted intersection sum..." << std::endl;
  ::private_join_and_compute::ServerRoundTwo server_round_two;
  ::grpc::ClientContext server_round_two_client_context;
  status = stub->ExecuteServerRoundTwo(&server_round_two_client_context,
                                       client_round_one, &server_round_two);
  if (!status.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to ExecuteServerRoundTwo: "
              << status.error_message() << std::endl;
    return 1;
  }

  // Compute the intersection size and sum.
  std::cout << "Client: Received response from the server. Decrypting the "
               "intersection-sum."
            << std::endl;
  auto maybe_intersection_size_and_sum = client->DecryptSum(server_round_two);
  if (!maybe_intersection_size_and_sum.ok()) {
    std::cerr << "Client::ExecuteProtocol: failed to DecryptSum: "
              << maybe_intersection_size_and_sum.status() << std::endl;
    return 1;
  }
  auto intersection_size_and_sum =
      std::move(maybe_intersection_size_and_sum.ValueOrDie());

  // Output the result.

  int64_t intersection_size = intersection_size_and_sum.first;
  auto maybe_intersection_sum = intersection_size_and_sum.second.ToIntValue();
  if (!maybe_intersection_sum.ok()) {
    std::cerr
        << "Client::ExecuteProtocol: failed to recover the intersection sum: "
        << maybe_intersection_sum.status() << std::endl;
    return 1;
  }

  std::cout << "Client: The intersection size is " << intersection_size
            << " and the intersection-sum is "
            << maybe_intersection_sum.ValueOrDie() << std::endl;

  return 0;
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  return ExecuteProtocol();
}
