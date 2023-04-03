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
#include <thread>  // NOLINT
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "private_join_and_compute/data_util.h"
#include "private_join_and_compute/private_join_and_compute.grpc.pb.h"
#include "private_join_and_compute/private_join_and_compute_rpc_impl.h"
#include "private_join_and_compute/protocol_server.h"
#include "private_join_and_compute/server_impl.h"

ABSL_FLAG(std::string, port, "0.0.0.0:10501", "Port on which to listen");
ABSL_FLAG(std::string, server_data_file, "",
          "The file from which to read the server database.");

int RunServer() {
  std::cout << "Server: loading data... " << std::endl;
  auto maybe_server_identifiers =
      ::private_join_and_compute::ReadServerDatasetFromFile(
          absl::GetFlag(FLAGS_server_data_file));
  if (!maybe_server_identifiers.ok()) {
    std::cerr << "RunServer: failed " << maybe_server_identifiers.status()
              << std::endl;
    return 1;
  }

  ::private_join_and_compute::Context context;
  std::unique_ptr<::private_join_and_compute::ProtocolServer> server =
      std::make_unique<
          ::private_join_and_compute::PrivateIntersectionSumProtocolServerImpl>(
          &context, std::move(maybe_server_identifiers.value()));
  ::private_join_and_compute::PrivateJoinAndComputeRpcImpl service(
      std::move(server));

  ::grpc::ServerBuilder builder;
  // Consider grpc::SslServerCredentials if not running locally.
  builder.AddListeningPort(absl::GetFlag(FLAGS_port),
                           ::grpc::experimental::LocalServerCredentials(
                               grpc_local_connect_type::LOCAL_TCP));
  builder.RegisterService(&service);
  std::unique_ptr<::grpc::Server> grpc_server(builder.BuildAndStart());

  // Run the server on a background thread.
  std::thread grpc_server_thread(
      [](::grpc::Server* grpc_server_ptr) {
        std::cout << "Server: listening on " << absl::GetFlag(FLAGS_port)
                  << std::endl;
        grpc_server_ptr->Wait();
      },
      grpc_server.get());

  while (!service.protocol_finished()) {
    // Wait for the server to be done, and then shut the server down.
  }

  // Shut down server.
  grpc_server->Shutdown();
  grpc_server_thread.join();
  std::cout << "Server completed protocol and shut down." << std::endl;

  return 0;
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  return RunServer();
}
