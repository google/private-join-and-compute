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

#include "private_join_and_compute/private_join_and_compute_rpc_impl.h"

#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

namespace {
// Translates Status to grpc::Status
::grpc::Status ConvertStatus(const Status& status) {
  if (status.ok()) {
    return ::grpc::Status::OK;
  }
  if (IsInvalidArgument(status)) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          std::string(status.message()));
  }
  if (IsInternal(status)) {
    return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                          std::string(status.message()));
  }
  return ::grpc::Status(::grpc::StatusCode::UNKNOWN,
                        std::string(status.message()));
}

class SingleMessageSink : public MessageSink<ServerMessage> {
 public:
  explicit SingleMessageSink(ServerMessage* server_message)
      : server_message_(server_message) {}

  ~SingleMessageSink() override = default;

  Status Send(const ServerMessage& server_message) override {
    if (!message_sent_) {
      *server_message_ = server_message;
      message_sent_ = true;
      return OkStatus();
    } else {
      return InvalidArgumentError(
          "SingleMessageSink can only accept a single message.");
    }
  }

 private:
  ServerMessage* server_message_ = nullptr;
  bool message_sent_ = false;
};

}  // namespace

::grpc::Status PrivateJoinAndComputeRpcImpl::Handle(
    ::grpc::ServerContext* context, const ClientMessage* request,
    ServerMessage* response) {
  SingleMessageSink message_sink(response);
  auto status = protocol_server_impl_->Handle(*request, &message_sink);
  return ConvertStatus(status);
}

}  // namespace private_join_and_compute
