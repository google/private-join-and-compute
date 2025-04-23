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

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MACROS_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MACROS_H_

#include "absl/base/port.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

// Helper macro that checks if the right hand side (rexpression) evaluates to a
// StatusOr with Status OK, and if so assigns the value to the value on the left
// hand side (lhs), otherwise returns the error status. Example:
//   PJC_ASSIGN_OR_RETURN(lhs, rexpression);
#ifndef PJC_ASSIGN_OR_RETURN
#define PJC_ASSIGN_OR_RETURN(lhs, rexpr)                                       \
  PRIVATE_JOIN_AND_COMPUTE_ASSIGN_OR_RETURN_IMPL_(                         \
      PRIVATE_JOIN_AND_COMPUTE_STATUS_MACROS_IMPL_CONCAT_(status_or_value, \
                                                          __LINE__),       \
      lhs, rexpr)

// Internal helper.
#define PRIVATE_JOIN_AND_COMPUTE_ASSIGN_OR_RETURN_IMPL_(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                                    \
  if (ABSL_PREDICT_FALSE(!statusor.ok())) {                                   \
    return std::move(statusor).status();                                      \
  }                                                                           \
  lhs = *std::move(statusor)
#endif  // PJC_ASSIGN_OR_RETURN

// Helper macro that checks if the given expression evaluates to a
// Status with Status OK. If not,  returns the error status. Example:
//   RETURN_IF_ERROR(expression);
#ifndef RETURN_IF_ERROR
#define RETURN_IF_ERROR(expr)                                           \
  PRIVATE_JOIN_AND_COMPUTE_RETURN_IF_ERROR_IMPL_(                       \
      PRIVATE_JOIN_AND_COMPUTE_STATUS_MACROS_IMPL_CONCAT_(status_value, \
                                                          __LINE__),    \
      expr)

// Internal helper.
#define PRIVATE_JOIN_AND_COMPUTE_RETURN_IF_ERROR_IMPL_(status, expr) \
  auto status = (expr);                                              \
  if (ABSL_PREDICT_FALSE(!status.ok())) {                            \
    return status;                                                   \
  }
#endif  // RETURN_IF_ERROR

// Internal helper for concatenating macro values.
#define PRIVATE_JOIN_AND_COMPUTE_STATUS_MACROS_IMPL_CONCAT_INNER_(x, y) x##y
#define PRIVATE_JOIN_AND_COMPUTE_STATUS_MACROS_IMPL_CONCAT_(x, y) \
  PRIVATE_JOIN_AND_COMPUTE_STATUS_MACROS_IMPL_CONCAT_INNER_(x, y)

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MACROS_H_
