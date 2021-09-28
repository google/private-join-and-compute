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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/util/file.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace {

class PosixFile : public File {
 public:
  PosixFile() : File(), f_(nullptr), current_fname_() {}

  ~PosixFile() override {
    if (f_) Close().IgnoreError();
  }

  Status Open(absl::string_view file_name, absl::string_view mode) final {
    if (nullptr != f_) {
      return InternalError(
          absl::StrCat("Open failed:", "File with name ", current_fname_,
                       " has already been opened, close it first."));
    }
    f_ = fopen(file_name.data(), mode.data());
    if (nullptr == f_) {
      return absl::NotFoundError(
          absl::StrCat("Open failed:", "Error opening file ", file_name));
    }
    current_fname_ = std::string(file_name);
    return OkStatus();
  }

  Status Close() final {
    if (nullptr == f_) {
      return InternalError(
          absl::StrCat("Close failed:", "There is no opened file."));
    }
    if (fclose(f_)) {
      return InternalError(
          absl::StrCat("Close failed:", "Error closing file ", current_fname_));
    }
    f_ = nullptr;
    return OkStatus();
  }

  StatusOr<bool> HasMore() final {
    if (nullptr == f_) {
      return InternalError(
          absl::StrCat("HasMore failed:", "There is no opened file."));
    }
    if (feof(f_)) return false;
    if (ferror(f_)) {
      return InternalError(absl::StrCat(
          "HasMore failed:", "Error indicator has been set for file ",
          current_fname_));
    }
    int c = getc(f_);
    if (ferror(f_)) {
      return InternalError(absl::StrCat(
          "HasMore failed:", "Error reading a single character from the file ",
          current_fname_));
    }
    if (ungetc(c, f_) != c) {
      return InternalError(absl::StrCat(
          "HasMore failed:", "Error putting back the peeked character ",
          "into the file ", current_fname_));
    }
    return c != EOF;
  }

  StatusOr<std::string> Read(size_t length) final {
    if (nullptr == f_) {
      return InternalError(
          absl::StrCat("Read failed:", "There is no opened file."));
    }
    std::vector<char> data(length);
    if (fread(data.data(), 1, length, f_) != length) {
      return InternalError(absl::StrCat(
          "condition failed:", "Error reading the file ", current_fname_));
    }
    return std::string(data.begin(), data.end());
  }

  StatusOr<std::string> ReadLine() final {
    if (nullptr == f_) {
      return InternalError(
          absl::StrCat("ReadLine failed:", "There is no opened file."));
    }
    if (fgets(buffer_, LINE_MAX, f_) == nullptr || ferror(f_)) {
      return InternalError(
          absl::StrCat("ReadLine failed:", "Error reading line from the file ",
                       current_fname_));
    }
    std::string content;
    int len = strlen(buffer_);
    // Remove trailing '\n' if present.
    if (len > 0 && buffer_[len - 1] == '\n') {
      // Remove trailing '\r' if present (e.g. on Windows)
      if (len > 1 && buffer_[len - 2] == '\r') {
        content.append(buffer_, len - 2);
      } else {
        content.append(buffer_, len - 1);
      }
    } else {
      // No trailing newline characters
      content.append(buffer_, len);
    }
    return content;
  }

  Status Write(absl::string_view content, size_t length) final {
    if (nullptr == f_) {
      return InternalError(
          absl::StrCat("ReadLine failed:", "There is no opened file."));
    }
    if (fwrite(content.data(), 1, length, f_) != length) {
      return InternalError(absl::StrCat(
          "ReadLine failed:", "Error writing the given data into the file ",
          current_fname_));
    }
    return OkStatus();
  }

 private:
  FILE* f_;
  std::string current_fname_;
  char buffer_[LINE_MAX];
};

}  // namespace

File* File::GetFile() { return new PosixFile(); }

Status RenameFile(absl::string_view from, absl::string_view to) {
  if (0 != rename(from.data(), to.data())) {
    return InternalError(absl::StrCat(
        "RenameFile failed:", "Cannot rename file, ", from, " to file, ", to));
  }
  return OkStatus();
}

Status DeleteFile(absl::string_view file_name) {
  if (0 != remove(file_name.data())) {
    return InternalError(
        absl::StrCat("DeleteFile failed:", "Cannot delete file, ", file_name));
  }
  return OkStatus();
}

}  // namespace private_join_and_compute
