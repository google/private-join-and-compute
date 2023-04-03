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

#include "private_join_and_compute/util/process_record_file_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "private_join_and_compute/util/process_record_file_parameters.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/status_testing.inc"
#include "private_join_and_compute/util/test.pb.h"

namespace private_join_and_compute::util::process_file_util {
namespace {

using proto::test::IntValueProto;
using proto::test::StringValueProto;

auto record_transformer = [](IntValueProto proto) {
  StringValueProto result;
  result.set_prefix(proto.prefix());
  result.set_value(std::to_string(proto.value()).append("_bla"));
  return result;
};

void writeValues(absl::string_view input_file) {
  IntValueProto v1;
  v1.set_prefix(1);
  v1.set_value(9);
  IntValueProto v2;
  v2.set_prefix(2);
  v2.set_value(4);
  IntValueProto v3;
  v3.set_prefix(3);
  v3.set_value(7);
  auto writer = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  ASSERT_OK(writer->Open(input_file));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(v2)));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(v1)));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(v3)));
  ASSERT_OK(writer->Close());
}

TEST(ProcessRecordFileTest, FileDoesNotExist) {
  ProcessRecordFileParameters params;
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string input_file = (temp_dir / "input_1.proto").string();
  std::string output_file = (temp_dir / "output_1.proto").string();

  auto status =
      process_file_util::ProcessRecordFile<IntValueProto, StringValueProto>(
          record_transformer, params, input_file, output_file);

  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kNotFound);
}

TEST(ProcessRecordFileTest, TestProcessesFile) {
  ProcessRecordFileParameters params;
  params.data_chunk_size = 2;
  params.thread_count = 2;
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string input_file = (temp_dir / "input_2.proto").string();
  std::string output_file = (temp_dir / "output_2.proto").string();

  writeValues(input_file);

  auto status =
      process_file_util::ProcessRecordFile<IntValueProto, StringValueProto>(
          record_transformer, params, input_file, output_file);
  ASSERT_OK(status);

  ASSERT_TRUE(std::filesystem::exists(output_file));
  // Check intermediate file was deleted.
  ASSERT_FALSE(std::filesystem::exists(output_file + "0"));

  auto reader = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  ASSERT_OK(reader->Open(output_file));

  StringValueProto s1;
  s1.set_prefix(1);
  s1.set_value("9_bla");
  StringValueProto s2;
  s2.set_prefix(2);
  s2.set_value("4_bla");
  StringValueProto s3;
  s3.set_prefix(3);
  s3.set_value("7_bla");
  std::vector<std::string> expected_result{ProtoUtils::ToString(s1),
                                           ProtoUtils::ToString(s2),
                                           ProtoUtils::ToString(s3)};

  std::vector<std::string> actual_result;
  while (reader->HasMore().value()) {
    std::string raw_record;
    ASSERT_OK(reader->Read(&raw_record));
    actual_result.push_back(raw_record);
  }
  EXPECT_OK(reader->Close());
  ASSERT_EQ(expected_result, actual_result);

  // Remove all files.
  std::filesystem::remove(input_file);
  std::filesystem::remove(output_file);
}

TEST(ProcessRecordFileTest, TestCustomSortKey) {
  ProcessRecordFileParameters params;
  params.data_chunk_size = 1;
  params.thread_count = 1;
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string input_file = (temp_dir / "input_3.proto").string();
  std::string output_file = (temp_dir / "output_3.proto").string();

  writeValues(input_file);

  auto get_sorting_key_function = [](absl::string_view raw_record) {
    return ProtoUtils::FromString<StringValueProto>(raw_record).value();
  };
  auto status =
      process_file_util::ProcessRecordFile<IntValueProto, StringValueProto>(
          record_transformer, params, input_file, output_file,
          get_sorting_key_function);
  ASSERT_OK(status);

  ASSERT_TRUE(std::filesystem::exists(output_file));

  StringValueProto s1;
  s1.set_prefix(1);
  s1.set_value("9_bla");
  StringValueProto s2;
  s2.set_prefix(2);
  s2.set_value("4_bla");
  StringValueProto s3;
  s3.set_prefix(3);
  s3.set_value("7_bla");
  std::vector<std::string> expected_result{ProtoUtils::ToString(s2),
                                           ProtoUtils::ToString(s3),
                                           ProtoUtils::ToString(s1)};

  auto reader = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  ASSERT_OK(reader->Open(output_file));
  std::vector<std::string> actual_result;
  while (reader->HasMore().value()) {
    std::string raw_record;
    ASSERT_OK(reader->Read(&raw_record));
    actual_result.push_back(raw_record);
  }
  EXPECT_OK(reader->Close());
  ASSERT_EQ(expected_result, actual_result);

  // Remove all files.
  std::filesystem::remove(input_file);
  std::filesystem::remove(output_file);
}

}  // namespace
}  // namespace private_join_and_compute::util::process_file_util
