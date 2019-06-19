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

#include "private_join_and_compute_rpc_impl.h"

#include "util/status.inc"

namespace private_join_and_compute {

namespace {
// Translates util::Status to grpc::Status
::grpc::Status ConvertStatus(const util::Status& status) {
  if (status.ok()) {
    return ::grpc::Status::OK;
  }
  if (util::IsInvalidArgument(status)) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          std::string(status.message()));
  }
  if (util::IsInternal(status)) {
    return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                          std::string(status.message()));
  }
  return ::grpc::Status(::grpc::StatusCode::UNKNOWN,
                        std::string(status.message()));
}
}  // namespace

::grpc::Status PrivateJoinAndComputeRpcImpl::StartProtocol(
    ::grpc::ServerContext* context, const StartProtocolRequest* request,
    ServerRoundOne* response) {
  auto maybe_response = server_->EncryptSet();
  if (maybe_response.ok()) {
    *response = std::move(maybe_response.ValueOrDie());
  }
  return ConvertStatus(maybe_response.status());
}

::grpc::Status PrivateJoinAndComputeRpcImpl::ExecuteServerRoundTwo(
    ::grpc::ServerContext* context, const ClientRoundOne* request,
    ServerRoundTwo* response) {
  if (protocol_finished_) {
    return ::grpc::Status(
        ::grpc::StatusCode::INVALID_ARGUMENT,
        "PrivateJoinAndComputeRpcImpl: Protocol is already finished.");
  }

  auto maybe_response = server_->ComputeIntersection(*request);
  if (maybe_response.ok()) {
    *response = std::move(maybe_response.ValueOrDie());
    protocol_finished_ = true;
  }
  return ConvertStatus(maybe_response.status());
}

}  // namespace private_join_and_compute
