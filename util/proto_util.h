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

// Protocol buffer related static utility functions.

#ifndef INTERNAL_UTIL_PROTO_UTIL_H_
#define INTERNAL_UTIL_PROTO_UTIL_H_

#include <sstream>
#include <string>

#include "absl/strings/string_view.h"
#include "src/google/protobuf/message_lite.h"

namespace private_join_and_compute {

class ProtoUtils {
 public:
  template <typename ProtoType>
  static ProtoType FromString(absl::string_view raw_data);

  static std::string ToString(const google::protobuf::MessageLite& record);
};

template <typename ProtoType>
inline ProtoType ProtoUtils::FromString(absl::string_view raw_data) {
  ProtoType record;
  record.ParseFromArray(raw_data.data(), raw_data.size());
  return record;
}

inline std::string ProtoUtils::ToString(
    const google::protobuf::MessageLite& record) {
  std::ostringstream record_str_stream;
  record.SerializeToOstream(&record_str_stream);
  return record_str_stream.str();
}

}  // namespace private_join_and_compute

#endif  // INTERNAL_UTIL_PROTO_UTIL_H_
