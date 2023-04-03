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

#include "private_join_and_compute/util/recordio.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "absl/random/random.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/util/file_test.pb.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace {

using ::private_join_and_compute::testing::TestProto;
using ::testing::ElementsAreArray;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using testing::IsOkAndHolds;
using testing::StatusIs;
using ::testing::TempDir;

std::string GetTestPBWithDummyAsStr(absl::string_view data,
                                    absl::string_view dummy) {
  TestProto test_proto;
  test_proto.set_record(std::string(data));
  test_proto.set_dummy(std::string(dummy));
  return ProtoUtils::ToString(test_proto);
}

void ExpectFileContainsRecords(absl::string_view filename,
                               const std::vector<std::string>& expected_ids) {
  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  std::vector<std::string> ids_read;
  EXPECT_OK(reader->Open(filename));
  while (reader->HasMore().value()) {
    std::string raw_record;
    EXPECT_OK(reader->Read(&raw_record));
    ids_read.push_back(ProtoUtils::FromString<TestProto>(raw_record).record());
  }
  EXPECT_THAT(ids_read, ElementsAreArray(expected_ids));
}

TestProto GetRecord(absl::string_view id) {
  TestProto record;
  record.set_record(std::string(id));
  return record;
}

void ExpectInternalErrorWithSubstring(const Status& status,
                                      absl::string_view substring) {
  EXPECT_THAT(status, StatusIs(private_join_and_compute::StatusCode::kInternal,
                               HasSubstr(substring)));
}

TEST(FileTest, WriteRecordThenReadTest) {
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rw->Write("data"));
  EXPECT_OK(rw->Close());
  auto rr = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
  std::string actual;
  EXPECT_OK(rr->Read(&actual));
  EXPECT_EQ("data", actual);
  EXPECT_OK(rr->Close());
}

TEST(FileTest, CannotOpenIfAlreadyOpened) {
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rw->Write("data"));
  EXPECT_OK(rw->Close());
  auto rr = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
  EXPECT_FALSE(rr->Open(TempDir() + "test_file.txt").ok());
}

TEST(FileTest, OpensIfClosed) {
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rw->Write("data"));
  EXPECT_OK(rw->Close());
  auto rr = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rr->Close());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
}

TEST(FileTest, WriteMultipleRecordsThenReadTest) {
  Context ctx;
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rw->Write("the first record."));
  char written2_char[] = "raw\0record";
  std::string written2(written2_char, 10);
  EXPECT_OK(rw->Write(written2));
  std::string num_bytes = ctx.CreateBigNum(1111111111).ToBytes();
  EXPECT_OK(rw->Write(num_bytes));
  EXPECT_OK(rw->Close());
  auto rr = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
  std::string read;
  EXPECT_TRUE(rr->HasMore().value());
  EXPECT_OK(rr->Read(&read));
  EXPECT_EQ("the first record.", read);
  EXPECT_TRUE(rr->HasMore().value());
  std::string raw_read;
  EXPECT_OK(rr->Read(&raw_read));
  EXPECT_EQ(written2, raw_read);
  EXPECT_NE("raw", raw_read);
  EXPECT_EQ(10, raw_read.size());
  EXPECT_TRUE(rr->HasMore().value());
  EXPECT_OK(rr->Read(&read));
  EXPECT_EQ(num_bytes, read);
  EXPECT_FALSE(rr->HasMore().value());
  EXPECT_OK(rr->Close());
}

TEST(FileTest, MultiSortReaderReadsInSortedOrder) {
  std::vector<std::string> filenames({TempDir() + "test_file0",
                                      TempDir() + "test_file1",
                                      TempDir() + "test_file2"});
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(filenames[0]));
  std::vector<std::string> records(
      {std::string("1\00", 3), std::string("1\01", 3), std::string("1\02", 3),
       std::string("1\03", 3), std::string("1\04", 3), std::string("1\05", 3)});
  EXPECT_OK(rw->Write(records[4]));
  EXPECT_OK(rw->Write(records[5]));
  EXPECT_OK(rw->Close());
  EXPECT_OK(rw->Open(filenames[1]));
  EXPECT_OK(rw->Write(records[2]));
  EXPECT_OK(rw->Write(records[3]));
  EXPECT_OK(rw->Close());
  EXPECT_OK(rw->Open(filenames[2]));
  EXPECT_OK(rw->Write(records[0]));
  EXPECT_OK(rw->Write(records[1]));
  EXPECT_OK(rw->Close());
  auto msr = std::unique_ptr<MultiSortedReader<std::string>>(
      MultiSortedReader<std::string>::Get());
  EXPECT_OK(msr->Open(filenames));
  std::string data;
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[0], data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[1], data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[2], data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[3], data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[4], data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(records[5], data);
  EXPECT_FALSE(msr->HasMore().value());
  EXPECT_FALSE(msr->Open(filenames).ok());
  EXPECT_OK(msr->Close());
  EXPECT_OK(msr->Open(filenames));
  EXPECT_OK(msr->Close());
}

TEST(FileTest, MultiSortReaderSortsBasedOnProtoKeyField) {
  std::vector<std::string> filenames({
      TempDir() + "test_file0",
      TempDir() + "test_file1",
  });
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(filenames[0]));
  EXPECT_OK(rw->Write(GetTestPBWithDummyAsStr("1", "tiny")));
  EXPECT_OK(rw->Write(GetTestPBWithDummyAsStr("3", "ti")));
  EXPECT_OK(rw->Close());
  EXPECT_OK(rw->Open(filenames[1]));
  EXPECT_OK(rw->Write(GetTestPBWithDummyAsStr("2", "tin")));
  EXPECT_OK(rw->Write(GetTestPBWithDummyAsStr("4", "t")));
  EXPECT_OK(rw->Close());
  auto msr = std::unique_ptr<MultiSortedReader<std::string>>(
      MultiSortedReader<std::string>::Get());
  EXPECT_OK(msr->Open(filenames, [](absl::string_view raw_data) {
    return ProtoUtils::FromString<TestProto>(raw_data).record();
  }));
  std::string data;
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(GetTestPBWithDummyAsStr("1", "tiny"), data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(GetTestPBWithDummyAsStr("2", "tin"), data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(GetTestPBWithDummyAsStr("3", "ti"), data);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data));
  EXPECT_EQ(GetTestPBWithDummyAsStr("4", "t"), data);
  EXPECT_FALSE(msr->HasMore().value());
  EXPECT_OK(msr->Close());
}

TEST(FileTest, MultiSortReaderReadsIndicesAsWell) {
  std::vector<std::string> filenames({
      TempDir() + "test_file0",
      TempDir() + "test_file1",
  });
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(filenames[0]));
  EXPECT_OK(rw->Write("1"));
  EXPECT_OK(rw->Write("3"));
  EXPECT_OK(rw->Close());
  EXPECT_OK(rw->Open(filenames[1]));
  EXPECT_OK(rw->Write("2"));
  EXPECT_OK(rw->Close());
  auto msr = std::unique_ptr<MultiSortedReader<std::string>>(
      MultiSortedReader<std::string>::Get());
  EXPECT_OK(msr->Open(filenames));
  std::string data;
  int index;
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(0, index);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(1, index);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(0, index);
  EXPECT_FALSE(msr->HasMore().value());
  EXPECT_OK(msr->Close());
}

TEST(FileTest, MultiSortReaderReadsDuplicateRecordsInOrderOfTheFileIndex) {
  std::vector<std::string> filenames({
      TempDir() + "test_file0",
      TempDir() + "test_file1",
  });
  auto rw = std::unique_ptr<RecordWriter>(RecordWriter::Get());
  EXPECT_OK(rw->Open(filenames[0]));
  EXPECT_OK(rw->Write("1"));
  EXPECT_OK(rw->Write("2"));
  EXPECT_OK(rw->Close());
  EXPECT_OK(rw->Open(filenames[1]));
  EXPECT_OK(rw->Write("2"));
  EXPECT_OK(rw->Close());
  auto msr = std::unique_ptr<MultiSortedReader<std::string>>(
      MultiSortedReader<std::string>::Get());
  EXPECT_OK(msr->Open(filenames));
  std::string data;
  int index;
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(0, index);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(1, index);
  EXPECT_TRUE(msr->HasMore().value());
  EXPECT_OK(msr->Read(&data, &index));
  EXPECT_EQ(0, index);
  EXPECT_FALSE(msr->HasMore().value());
  EXPECT_OK(msr->Close());
}

TEST(FileTest, LineReaderTest) {
  std::ofstream ofs(TempDir() + "test_file.txt");
  ofs << "Line1\nLine2\n\n";
  ofs.close();
  auto lr = std::unique_ptr<RecordReader>(RecordReader::GetLineReader());
  EXPECT_OK(lr->Open(TempDir() + "test_file.txt"));
  std::string line;
  EXPECT_TRUE(lr->HasMore().value());
  EXPECT_OK(lr->Read(&line));
  EXPECT_EQ("Line1", line);
  EXPECT_TRUE(lr->HasMore().value());
  EXPECT_OK(lr->Read(&line));
  EXPECT_EQ("Line2", line);
  EXPECT_TRUE(lr->HasMore().value());
  EXPECT_OK(lr->Read(&line));
  EXPECT_EQ("", line);
  EXPECT_FALSE(lr->HasMore().value());
  EXPECT_OK(lr->Close());
}

TEST(FileTest, LineReaderTestWithoutNewline) {
  std::ofstream ofs(TempDir() + "test_file.txt");
  ofs << "Line1\nLine2";
  ofs.close();
  auto lr = std::unique_ptr<RecordReader>(RecordReader::GetLineReader());
  EXPECT_OK(lr->Open(TempDir() + "test_file.txt"));
  std::string line;
  EXPECT_TRUE(lr->HasMore().value());
  EXPECT_OK(lr->Read(&line));
  EXPECT_EQ("Line1", line);
  EXPECT_TRUE(lr->HasMore().value());
  EXPECT_OK(lr->Read(&line));
  EXPECT_EQ("Line2", line);
  EXPECT_FALSE(lr->HasMore().value());
  EXPECT_OK(lr->Close());
}

TEST(FileTest, LineWriterTest) {
  auto rw = std::unique_ptr<LineWriter>(LineWriter::Get());
  EXPECT_OK(rw->Open(TempDir() + "test_file.txt"));
  EXPECT_OK(rw->Write("data"));
  EXPECT_OK(rw->Close());
  auto rr = std::unique_ptr<RecordReader>(RecordReader::GetLineReader());
  EXPECT_OK(rr->Open(TempDir() + "test_file.txt"));
  std::string actual;
  EXPECT_OK(rr->Read(&actual));
  EXPECT_EQ("data", actual);
  EXPECT_OK(rr->Close());
}

TEST(ShardingWriterTest, WritesInShards) {
  auto writer = ShardingWriter<std::string>::Get(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      /*max_bytes=*/1);
  writer->SetShardPrefix(TempDir() + "test_file");

  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("22"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("33"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("11"))));
  EXPECT_THAT(writer->Close(),
              IsOkAndHolds(ElementsAreArray({TempDir() + "test_file0",
                                             TempDir() + "test_file1",
                                             TempDir() + "test_file2"})));

  ExpectFileContainsRecords(TempDir() + "test_file0", {"22"});
  ExpectFileContainsRecords(TempDir() + "test_file1", {"33"});
  ExpectFileContainsRecords(TempDir() + "test_file2", {"11"});
}

TEST(ShardingWriterTest, WritesInSortedShards) {
  auto writer = ShardingWriter<std::string>::Get(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      /*max_bytes=*/100);
  writer->SetShardPrefix(TempDir() + "test_file");

  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("22"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("33"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("11"))));
  EXPECT_THAT(writer->Close(),
              IsOkAndHolds(ElementsAreArray({TempDir() + "test_file0"})));

  ExpectFileContainsRecords(TempDir() + "test_file0", {"11", "22", "33"});
}

TEST(ShardingWriterTest, CreatesNoShardsWhenNoRecordsWritten) {
  auto writer = ShardingWriter<std::string>::Get(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      /*max_bytes=*/1);
  writer->SetShardPrefix(TempDir() + "test_file");
  EXPECT_THAT(writer->Close(), IsOkAndHolds(IsEmpty()));
}

TEST(ShardingWriterTest, FailsIfWriteBeforeSettingOutputFilenames) {
  auto writer = ShardingWriter<std::string>::Get(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      /*max_bytes=*/100);
  ExpectInternalErrorWithSubstring(
      writer->Write(ProtoUtils::ToString(GetRecord("22"))),
      "Must call SetShardPrefix before calling Write.");
}

TEST(ShardingWriterTest, FailsIfCloseBeforeSettingOutputFilenames) {
  auto writer = ShardingWriter<std::string>::Get(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      /*max_bytes=*/100);
  ExpectInternalErrorWithSubstring(
      writer->Close().status(),
      "Must call SetShardPrefix before calling Close.");
}

TEST(ShardingMergerTest, MergesMultipleFilesCorrectly) {
  std::unique_ptr<RecordWriter> writer(RecordWriter::Get());
  EXPECT_OK(writer->Open(TempDir() + "test_file0"));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("22"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("44"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("66"))));
  EXPECT_OK(writer->Close());
  EXPECT_OK(writer->Open(TempDir() + "test_file1"));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("11"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("77"))));
  EXPECT_OK(writer->Write(ProtoUtils::ToString(GetRecord("99"))));
  EXPECT_OK(writer->Close());

  ShardMerger<std::string> merger;
  EXPECT_OK(merger.Merge(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      {TempDir() + "test_file0", TempDir() + "test_file1"},
      TempDir() + "output"));

  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  EXPECT_OK(reader->Open(TempDir() + "output"));
  std::string record;
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("11", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("22", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("44", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("66", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("77", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("99", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_FALSE(reader->HasMore().value());
  EXPECT_OK(reader->Close());
}

TEST(ShardingMergerTest, MergesSingleFileCorrectly) {
  std::unique_ptr<RecordWriter> writer(RecordWriter::Get());
  ASSERT_OK(writer->Open(TempDir() + "test_file0"));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(GetRecord("22"))));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(GetRecord("44"))));
  ASSERT_OK(writer->Write(ProtoUtils::ToString(GetRecord("66"))));
  ASSERT_OK(writer->Close());

  ShardMerger<std::string> merger;
  EXPECT_OK(merger.Merge(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      {TempDir() + "test_file0"}, TempDir() + "output"));

  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  EXPECT_OK(reader->Open(TempDir() + "output"));
  std::string record;
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("22", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("44", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_OK(reader->Read(&record));
  EXPECT_EQ("66", ProtoUtils::FromString<TestProto>(record).record());
  EXPECT_FALSE(reader->HasMore().value());
  EXPECT_OK(reader->Close());
}

TEST(ShardingMergerTest, CreatesEmptyFileIfNoShardsProvided) {
  ShardMerger<std::string> merger;
  EXPECT_OK(merger.Merge(
      [](absl::string_view raw_record) {
        return ProtoUtils::FromString<TestProto>(raw_record).record();
      },
      {} /* no shard files */, TempDir() + "output"));

  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  EXPECT_OK(reader->Open(TempDir() + "output"));
  EXPECT_FALSE(reader->HasMore().value());
  EXPECT_OK(reader->Close());
}

TEST(ShardingMergerTest, DeletesFiles) {
  std::unique_ptr<RecordWriter> writer(RecordWriter::Get());
  ASSERT_OK(writer->Open(TempDir() + "test_file0"));
  ASSERT_OK(writer->Close());
  ASSERT_OK(writer->Open(TempDir() + "test_file1"));
  ASSERT_OK(writer->Close());
  ASSERT_OK(writer->Open(TempDir() + "test_file2"));
  ASSERT_OK(writer->Close());

  ShardMerger<std::string> merger;
  EXPECT_OK(merger.Delete({TempDir() + "test_file0", TempDir() + "test_file1",
                           TempDir() + "test_file2"}));

  std::unique_ptr<RecordReader> reader(RecordReader::GetRecordReader());
  EXPECT_FALSE(reader->Open(TempDir() + "test_file0").ok());
  EXPECT_FALSE(reader->Open(TempDir() + "test_file1").ok());
  EXPECT_FALSE(reader->Open(TempDir() + "test_file2").ok());
}

}  // namespace
}  // namespace private_join_and_compute
