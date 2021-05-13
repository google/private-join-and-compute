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
#include "util/recordio.h"
#include "util/status.inc"

namespace private_join_and_compute {

class ProtoUtils {
 public:
  template <typename ProtoType>
  static ProtoType FromString(absl::string_view raw_data);

  static std::string ToString(const google::protobuf::MessageLite& record);

  template <typename ProtoType>
  static StatusOr<ProtoType> ReadProtoFromFile(absl::string_view filename);

  static Status WriteProtoToFile(const google::protobuf::MessageLite& record,
                                 absl::string_view filename);
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

template <typename ProtoType>
inline StatusOr<ProtoType> ProtoUtils::ReadProtoFromFile(
    absl::string_view filename) {
  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  RETURN_IF_ERROR(reader->Open(filename));
  std::string raw_record;
  RETURN_IF_ERROR(reader->Read(&raw_record));
  RETURN_IF_ERROR(reader->Close());
  return ProtoUtils::FromString<ProtoType>(raw_record);
}

inline Status ProtoUtils::WriteProtoToFile(
    const google::protobuf::MessageLite& record, absl::string_view filename) {
  std::unique_ptr<RecordWriter> writer(RecordWriter::Get());
  RETURN_IF_ERROR(writer->Open(filename));
  RETURN_IF_ERROR(writer->Write(ProtoUtils::ToString(record)));
  return writer->Close();
}
}  // namespace private_join_and_compute

#endif  // INTERNAL_UTIL_PROTO_UTIL_H_
