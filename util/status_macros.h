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

#ifndef UTIL_STATUS_MACROS_H_
#define UTIL_STATUS_MACROS_H_

#include "absl/base/port.h"
#include "util/status.inc"

// Helper macro that checks if condition is true, otherwise it returns a status
// with the given error_code.
// Example:
//   RET_ERROR_CHECK(condition, ::private_join_and_compute::StatusCode::kInternal) << message;
#define RET_ERROR_CHECK(condition, error_code)                        \
  while (ABSL_PREDICT_FALSE(!(condition)))                                 \
  return util::StatusBuilder(error_code)                     \
                 << #condition << " failed"

// Helper macro that checks if condition is true, otherwise it returns a status
// with INTERNAL error code.
// Example:
//   RET_INTERNAL_CHECK(condition) << message;
#define RET_INTERNAL_CHECK(condition)                        \
  RET_ERROR_CHECK(condition, ::private_join_and_compute::StatusCode::kInternal)

// Helper macro that checks if condition is true, otherwise it returns a status
// with INVALID_ARGUMENT error code.
// Example:
//   RET_INVALID_ARG_CHECK(condition) << message;
#define RET_INVALID_ARG_CHECK(condition)                              \
  while (ABSL_PREDICT_FALSE(!(condition)))                              \
  RET_ERROR_CHECK(condition, ::private_join_and_compute::StatusCode::kInvalidArgument)

// Helper macro that checks if val is not null. Val needs to return a pointer.
// If val is null, it returns an INVALID_ARGUMENT error code, otherwise it
// evaluates to val.

#define RETURN_IF_NULL(val)                                            \
  ({                                                                   \
    auto _val_result = (val);                                          \
    if (ABSL_PREDICT_FALSE(_val_result == nullptr)) {                       \
      return util::StatusBuilder(::private_join_and_compute::StatusCode::kInvalidArgument) \
             << #val " != nullptr"; \
    }                                                                  \
    _val_result;                                                       \
  })

namespace private_join_and_compute {
namespace internal {

// These helper functions allow RETURN_IF_ERROR to handle both util::Status and
// util::StatusOr.
inline ::util::Status ToStatus(const ::util::Status& s) { return s; }
template <typename T>
util::Status ToStatus(const ::util::StatusOr<T>& so) {
  return so.status();
}

inline void ToValue(::util::Status* status) {}

template <typename T>
inline T ToValue(::util::StatusOr<T>* statusor) {
  return statusor->ConsumeValueOrDie();
}

}  // namespace internal
}  // namespace private_join_and_compute

// Executes an expression that returns a util::StatusOr, extracting its value
// and returns it (or returns a Status message if the status is not ok).
//
// Example:
// MyClass val = RETURN_OR_ASSIGN(MaybeGetValue(...));
// If MaybeGetValue result is not ok then this stmt issues a return with the
// original status and it is autoboxed in a StatusOr.
// If the result is ok, then the result value of MaybeGetValue is unboxed and
// returned directly.
#define RETURN_OR_ASSIGN(expr)                            \
  ({                                                      \
    auto _val_result = (expr);                            \
    if (ABSL_PREDICT_FALSE(!_val_result.ok())) {          \
      return ::private_join_and_compute::internal::ToStatus(_val_result); \
    }                                                     \
    ::private_join_and_compute::internal::ToValue(&_val_result);          \
  })

#endif  // UTIL_STATUS_MACROS_H_
