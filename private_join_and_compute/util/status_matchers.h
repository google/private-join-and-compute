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

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MATCHERS_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MATCHERS_H_

#include <gmock/gmock.h>

#include <ostream>
#include <string>

#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace testing {

#ifdef GTEST_HAS_STATUS_MATCHERS

using ::testing::status::IsOk;
using ::testing::status::IsOkAndHolds;
using ::testing::status::StatusIs;

#else  // GTEST_HAS_STATUS_MATCHERS

namespace internal {

// This function and its overload allow the same matcher to be used for Status
// and StatusOr tests.
inline Status GetStatus(const Status& status) { return status; }

template <typename T>
inline Status GetStatus(const StatusOr<T>& statusor) {
  return statusor.status();
}

template <typename StatusType>
class StatusIsImpl : public ::testing::MatcherInterface<StatusType> {
 public:
  StatusIsImpl(const ::testing::Matcher<StatusCode>& code,
               const ::testing::Matcher<const std::string&>& message)
      : code_(code), message_(message) {}

  bool MatchAndExplain(
      StatusType status,
      ::testing::MatchResultListener* listener) const override {
    ::testing::StringMatchResultListener str_listener;
    Status real_status = GetStatus(status);
    if (!code_.MatchAndExplain(real_status.code(), &str_listener)) {
      *listener << str_listener.str();
      return false;
    }
    if (!message_.MatchAndExplain(
            static_cast<std::string>(real_status.message()), &str_listener)) {
      *listener << str_listener.str();
      return false;
    }
    return true;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "has a status code that ";
    code_.DescribeTo(os);
    *os << " and a message that ";
    message_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "has a status code that ";
    code_.DescribeNegationTo(os);
    *os << " and a message that ";
    message_.DescribeNegationTo(os);
  }

 private:
  ::testing::Matcher<StatusCode> code_;
  ::testing::Matcher<const std::string&> message_;
};

class StatusIsPoly {
 public:
  StatusIsPoly(::testing::Matcher<StatusCode>&& code,
               ::testing::Matcher<const std::string&>&& message)
      : code_(code), message_(message) {}

  // Converts this polymorphic matcher to a monomorphic matcher.
  template <typename StatusType>
  operator ::testing::Matcher<StatusType>() const {
    return ::testing::Matcher<StatusType>(
        new StatusIsImpl<StatusType>(code_, message_));
  }

 private:
  ::testing::Matcher<StatusCode> code_;
  ::testing::Matcher<const std::string&> message_;
};

}  // namespace internal

// This function allows us to avoid a template parameter when writing tests, so
// that we can transparently test both Status and StatusOr returns.
inline internal::StatusIsPoly StatusIs(
    ::testing::Matcher<StatusCode>&& code,
    ::testing::Matcher<const std::string&>&& message) {
  return internal::StatusIsPoly(
      std::forward< ::testing::Matcher<StatusCode> >(code),
      std::forward< ::testing::Matcher<const std::string&> >(message));
}

// Monomorphic implementation of matcher IsOkAndHolds(m).  StatusOrType is a
// reference to StatusOr<T>.
template <typename StatusOrType>
class IsOkAndHoldsMatcherImpl
    : public ::testing::MatcherInterface<StatusOrType> {
 public:
  typedef
      typename std::remove_reference<StatusOrType>::type::value_type value_type;

  template <typename InnerMatcher>
  explicit IsOkAndHoldsMatcherImpl(InnerMatcher&& inner_matcher)
      : inner_matcher_(::testing::SafeMatcherCast<const value_type&>(
            std::forward<InnerMatcher>(inner_matcher))) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is OK and has a value that ";
    inner_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "isn't OK or has a value that ";
    inner_matcher_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      StatusOrType actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    if (!actual_value.ok()) {
      *result_listener << "which has status " << actual_value.status();
      return false;
    }

    ::testing::StringMatchResultListener inner_listener;
    const bool matches =
        inner_matcher_.MatchAndExplain(*actual_value, &inner_listener);
    const std::string inner_explanation = inner_listener.str();
    if (!inner_explanation.empty()) {
      *result_listener << "which contains value "
                       << ::testing::PrintToString(*actual_value) << ", "
                       << inner_explanation;
    }
    return matches;
  }

 private:
  const ::testing::Matcher<const value_type&> inner_matcher_;
};

// Implements IsOkAndHolds(m) as a polymorphic matcher.
template <typename InnerMatcher>
class IsOkAndHoldsMatcher {
 public:
  explicit IsOkAndHoldsMatcher(InnerMatcher inner_matcher)
      : inner_matcher_(std::move(inner_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  StatusOrType can be either StatusOr<T> or a
  // reference to StatusOr<T>.
  template <typename StatusOrType>
  operator ::testing::Matcher<StatusOrType>() const {  // NOLINT
    return ::testing::Matcher<StatusOrType>(
        new IsOkAndHoldsMatcherImpl<const StatusOrType&>(inner_matcher_));
  }

 private:
  const InnerMatcher inner_matcher_;
};

// Monomorphic implementation of matcher IsOk() for a given type T.
// T can be Status, StatusOr<>, or a reference to either of them.
template <typename T>
class MonoIsOkMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  void DescribeTo(std::ostream* os) const override { *os << "is OK"; }
  void DescribeNegationTo(std::ostream* os) const override {
    *os << "is not OK";
  }
  bool MatchAndExplain(T actual_value,
                       ::testing::MatchResultListener*) const override {
    return GetStatus(actual_value).ok();
  }
};

// Implements IsOk() as a polymorphic matcher.
class IsOkMatcher {
 public:
  template <typename T>
  operator ::testing::Matcher<T>() const {  // NOLINT
    return ::testing::Matcher<T>(new MonoIsOkMatcherImpl<T>());
  }
};

// Returns a gMock matcher that matches a StatusOr<> whose status is
// OK and whose value matches the inner matcher.
template <typename InnerMatcher>
IsOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type> IsOkAndHolds(
    InnerMatcher&& inner_matcher) {
  return IsOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>(
      std::forward<InnerMatcher>(inner_matcher));
}

// Returns a gMock matcher that matches a Status or StatusOr<> which is OK.
inline IsOkMatcher IsOk() { return IsOkMatcher(); }

#endif  // GTEST_HAS_STATUS_MATCHERS

}  // namespace testing
}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_STATUS_MATCHERS_H_
