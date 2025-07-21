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

#include "private_join_and_compute/util/file.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace {

template <typename T1, typename T2>
void AssertOkAndHolds(const T1& expected_value, const StatusOr<T2>& status_or) {
  EXPECT_TRUE(status_or.ok()) << status_or.status();
  EXPECT_EQ(expected_value, status_or.value());
}

class FileTest : public testing::Test {
 public:
  FileTest() : testing::Test(), f_(File::GetFile()) {}

  std::unique_ptr<File> f_;
};

TEST_F(FileTest, WriteDataThenReadTest) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "wb").ok());
  EXPECT_TRUE(f_->Write("water", 4).ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "rb").ok());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("wat", f_->Read(3));
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("e", f_->Read(1));
  AssertOkAndHolds(false, f_->HasMore());
  EXPECT_TRUE(f_->Close().ok());
}

TEST_F(FileTest, ReadLineTest) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "wb").ok());
  EXPECT_TRUE(f_->Write("Line1\nLine2\n\n", 13).ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "r").ok());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line1", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line2", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("", f_->ReadLine());
  AssertOkAndHolds(false, f_->HasMore());
  EXPECT_TRUE(f_->Close().ok());
}

TEST_F(FileTest, CannotOpenFileIfAnotherFileIsAlreadyOpened) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "w").ok());
  EXPECT_FALSE(f_->Open(testing::TempDir() + "/tmp1.txt", "w").ok());
  EXPECT_TRUE(f_->Close().ok());
}

TEST_F(FileTest, AllOperationsFailWhenThereIsNoOpenedFile) {
  EXPECT_FALSE(f_->Close().ok());
  EXPECT_FALSE(f_->HasMore().ok());
  EXPECT_FALSE(f_->Read(1).ok());
  EXPECT_FALSE(f_->ReadLine().ok());
  EXPECT_FALSE(f_->Write("w", 1).ok());
}

TEST_F(FileTest, AllOperationsFailWhenThereIsNoOpenedFileAfterClosing) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "w").ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_FALSE(f_->Close().ok());
  EXPECT_FALSE(f_->HasMore().ok());
  EXPECT_FALSE(f_->Read(1).ok());
  EXPECT_FALSE(f_->ReadLine().ok());
  EXPECT_FALSE(f_->Write("w", 1).ok());
}

TEST_F(FileTest, TestRename) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "w").ok());
  EXPECT_TRUE(f_->Write("water", 5).ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_TRUE(RenameFile(testing::TempDir() + "/tmp.txt",
                         testing::TempDir() + "/tmp1.txt")
                  .ok());
  EXPECT_FALSE(f_->Open(testing::TempDir() + "/tmp.txt", "r").ok());
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp1.txt", "r").ok());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("water", f_->Read(5));
  AssertOkAndHolds(false, f_->HasMore());
  EXPECT_TRUE(f_->Close().ok());
}

TEST_F(FileTest, TestDelete) {
  // Create file and delete it.
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "w").ok());
  EXPECT_TRUE(f_->Write("water", 5).ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_TRUE(DeleteFile(testing::TempDir() + "/tmp.txt").ok());
  EXPECT_FALSE(f_->Open(testing::TempDir() + "/tmp.txt", "r").ok());

  // Try to delete nonexistent file.
  EXPECT_FALSE(DeleteFile(testing::TempDir() + "/tmp2.txt").ok());
}

TEST_F(FileTest, JoinPathWithMultipleArgs) {
  std::string ret = JoinPath("/tmp", "foo", "bar/", "/baz/");
  EXPECT_EQ("/tmp/foo.bar.baz", ret);
}

TEST_F(FileTest, JoinPathWithMultipleArgsStartingWithEndSlashDir) {
  std::string ret = JoinPath("/tmp/", "foo", "bar/", "/baz/");
  EXPECT_EQ("/tmp/foo.bar.baz", ret);
}

TEST_F(FileTest, ReadLineWithCarriageReturnsTest) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "wb").ok());
  std::string file_string = "Line1\nLine2\r\nLine3\r\nLine4\n\n";
  EXPECT_TRUE(f_->Write(file_string, file_string.size()).ok());
  EXPECT_TRUE(f_->Close().ok());
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/tmp.txt", "r").ok());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line1", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line2", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line3", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("Line4", f_->ReadLine());
  AssertOkAndHolds(true, f_->HasMore());
  AssertOkAndHolds("", f_->ReadLine());
  AssertOkAndHolds(false, f_->HasMore());
  EXPECT_TRUE(f_->Close().ok());
}

TEST_F(FileTest, FileDoesNotExist) {
  EXPECT_FALSE(FileExists(testing::TempDir() + "/nonexistent.txt").ok());
}

TEST_F(FileTest, FileExists) {
  EXPECT_TRUE(f_->Open(testing::TempDir() + "/newly_written.txt", "wb").ok());
  EXPECT_TRUE(f_->Write("water", 5).ok());
  EXPECT_TRUE(f_->Close().ok());
  // File exists after writing.
  EXPECT_TRUE(FileExists(testing::TempDir() + "/newly_written.txt").ok());
}

TEST_F(FileTest, WriteToUncreatedDirectoryFails) {
  // Write to uncreated directory.
  EXPECT_FALSE(
      f_->Open(testing::TempDir() + "/tmp/nonexsistent/tmp.txt", "wb").ok());
}

TEST_F(FileTest, RecursivelyCreateDir) {
  // Create a directory.
  EXPECT_TRUE(RecursivelyCreateDir(testing::TempDir() + "/tmp/dir1/dir2").ok());
  // Write to the directory.
  EXPECT_TRUE(
      f_->Open(testing::TempDir() + "/tmp/dir1/dir2/tmp.txt", "wb").ok());
  EXPECT_TRUE(f_->Write("water", 5).ok());
  EXPECT_TRUE(f_->Close().ok());
  // File exists after writing.
  EXPECT_TRUE(FileExists(testing::TempDir() + "/tmp/dir1/dir2/tmp.txt").ok());
}

}  // namespace
}  // namespace private_join_and_compute
