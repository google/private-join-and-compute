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

#include "absl/status/status.h"    // IWYU pragma: export
#include "absl/status/statusor.h"  // IWYU pragma: export

#include "private_join_and_compute/util/status_macros.h"

namespace private_join_and_compute {
// Aliases StatusCode to be compatible with our code.
using StatusCode = ::absl::StatusCode;
// Aliases Status, StatusOr and canonical errors. This alias exists for
// historical reasons (when this library had a fork of absl::Status).
using Status = absl::Status;
template <typename T>
using StatusOr = absl::StatusOr<T>;
using absl::InternalError;
using absl::InvalidArgumentError;
using absl::IsInternal;
using absl::IsInvalidArgument;
using absl::OkStatus;
}  // namespace private_join_and_compute


