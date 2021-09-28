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

/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_TESTING_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_TESTING_H_

#include <gmock/gmock.h>

#include "private_join_and_compute/util/status.inc"

#ifndef GTEST_HAS_STATUS_MATCHERS

#define ASSERT_OK(expr)                                                        \
  PRIVATE_JOIN_AND_COMPUTE_ASSERT_OK_IMPL_(                                    \
      PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_(_status, __LINE__), \
      expr)

#define PRIVATE_JOIN_AND_COMPUTE_ASSERT_OK_IMPL_(status, expr) \
  auto status = (expr);                                        \
  ASSERT_THAT(status.ok(), ::testing::Eq(true));

#define EXPECT_OK(expr)                                                        \
  PRIVATE_JOIN_AND_COMPUTE_EXPECT_OK_IMPL_(                                    \
      PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_(_status, __LINE__), \
      expr)

#define PRIVATE_JOIN_AND_COMPUTE_EXPECT_OK_IMPL_(status, expr) \
  auto status = (expr);                                        \
  EXPECT_THAT(status.ok(), ::testing::Eq(true));

#define ASSERT_OK_AND_ASSIGN(lhs, rexpr)                                     \
  PRIVATE_JOIN_AND_COMPUTE_ASSERT_OK_AND_ASSIGN_IMPL_(                       \
      PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_(_status_or_value, \
                                                           __LINE__),        \
      lhs, rexpr)

#define PRIVATE_JOIN_AND_COMPUTE_ASSERT_OK_AND_ASSIGN_IMPL_(statusor, lhs, \
                                                            rexpr)         \
  auto statusor = (rexpr);                                                 \
  ASSERT_THAT(statusor.ok(), ::testing::Eq(true));                         \
  lhs = std::move(statusor).value()

// Internal helper for concatenating macro values.
#define PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_INNER_(x, y) x##y
#define PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_(x, y) \
  PRIVATE_JOIN_AND_COMPUTE_STATUS_TESTING_IMPL_CONCAT_INNER_(x, y)

#endif  // GTEST_HAS_STATUS_MATCHERS

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_TESTING_H_
