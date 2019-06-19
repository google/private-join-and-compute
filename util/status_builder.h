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

#ifndef UTIL_STATUS_BUILDER_H_
#define UTIL_STATUS_BUILDER_H_

#include <limits>
#include <memory>
#include <sstream>
#include <utility>

#include "util/status.h"

namespace util {

class StatusBuilder {
 public:
  explicit StatusBuilder(::private_join_and_compute::StatusCode code);

  StatusBuilder(const StatusBuilder& sb);
  StatusBuilder& operator=(const StatusBuilder& sb);
  StatusBuilder(StatusBuilder&&) = default;
  StatusBuilder& operator=(StatusBuilder&&) = default;

  // Appends to the extra message that will be added to the original status.
  // The extra message is added to the original message as if by
  // `util::Annotate`, which includes a convenience separator between the
  // original message and the enriched one.
  template <typename T>
  StatusBuilder& operator<<(const T& value);

  // Returns true if the Status created by this builder will be ok().
  bool ok() const;

  // Returns the canonical code for the Status created by this builder.
  // Automatically converts to the canonical space if necessary.
  ::private_join_and_compute::StatusCode CanonicalCode() const;

  // Implicit conversion to Status.
  //
  // Careful: this operator has side effects, so it should be called at
  // most once.
  operator Status() const&;
  operator Status() &&;

 private:
  // Creates a Status from this builder.
  Status CreateStatus() &&;

  // The status that the result will be based on.  Can be modified by Attach().
  Status status_;

  // Gathers additional messages added with `<<` for use in the final status.
  std::ostringstream stream_;
};

// Implementation details follow; clients should ignore.

inline StatusBuilder::StatusBuilder(::private_join_and_compute::StatusCode code)
    : status_(code, "") {}

inline StatusBuilder::StatusBuilder(const StatusBuilder& sb)
    : status_(sb.status_) {
  stream_.str(sb.stream_.str());
}

inline StatusBuilder& StatusBuilder::operator=(const StatusBuilder& sb) {
  status_ = sb.status_;
  stream_.str(sb.stream_.str());
  return *this;
}

template <typename T>
StatusBuilder& StatusBuilder::operator<<(const T& value) {
  if (status_.ok()) return *this;
  stream_ << value;
  return *this;
}

inline bool StatusBuilder::ok() const { return status_.ok(); }

inline ::private_join_and_compute::StatusCode StatusBuilder::CanonicalCode() const {
  return status_.code();
}

inline StatusBuilder::operator Status() const& {
  return StatusBuilder(*this).CreateStatus();
}
inline StatusBuilder::operator Status() && {
  return std::move(*this).CreateStatus();
};

inline Status StatusBuilder::CreateStatus() && {
  return Annotate(status_, stream_.str());
}

}  // namespace util

#endif  // UTIL_STATUS_BUILDER_H_
