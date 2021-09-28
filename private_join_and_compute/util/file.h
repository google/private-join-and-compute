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

#ifndef PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_FILE_H_
#define PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_FILE_H_

#include <string>

#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// Renames a file. Overwrites the new file if it exists.
// Returns Status::OK for success.
// Error code in case of an error depends on the underlying implementation.
Status RenameFile(absl::string_view from, absl::string_view to);

// Deletes a file.
// Returns Status::OK for success.
// Error code in case of an error depends on the underlying implementation.
Status DeleteFile(absl::string_view file_name);

class File {
 public:
  virtual ~File() = default;

  // Opens the file_name for file operations applicable based on mode.
  // Returns Status::OK for success.
  // Error code in case of an error depends on the underlying implementation.
  virtual Status Open(absl::string_view file_name, absl::string_view mode) = 0;

  // Closes the opened file. Must be called after opening a file.
  // Returns Status::OK for success.
  // Error code in case of an error depends on the underlying implementation.
  virtual Status Close() = 0;

  // Returns true if there are more data in the file to be read.
  // Returns a status instead in case of an io error in determining if there is
  // more data.
  virtual StatusOr<bool> HasMore() = 0;

  // Returns a data string of size length from reading file if successful.
  // Returns a status in case of an error.
  // This would also return an error status if the read data size is less than
  // the length since it indicates file corruption.
  virtual StatusOr<std::string> Read(size_t length) = 0;

  // Returns a line as string from the file without the trailing '\n' (or "\r\n"
  // in the case of Windows).
  //
  // Returns a status in case of an error.
  virtual StatusOr<std::string> ReadLine() = 0;

  // Writes the given content of size length into the file.
  // Error code in case of an error depends on the underlying implementation.
  virtual Status Write(absl::string_view content, size_t length) = 0;

  // Returns a File object depending on the linked implementation.
  // Caller takes the ownership.
  static File* GetFile();

 protected:
  File() = default;
};

namespace internal {
std::string JoinPathImpl(std::initializer_list<std::string> paths);
}  // namespace internal

// Joins multiple paths together such that only the first argument directory
// structure is represented. A dot as a separator is added for other arguments.
//
//  Arguments                  | JoinPath            |
//  ---------------------------+---------------------+
//  '/foo', 'bar'              | /foo/bar            |
//  '/foo/', 'bar'             | /foo/bar            |
//  '/foo', '/bar'             | /foo/bar            |
//  '/foo', '/bar', '/baz'     | /foo/bar.baz        |
//
// All paths will be treated as relative paths, regardless of whether or not
// they start with a leading '/'. That is, all paths will be concatenated
// together, with the appropriate path separator inserted in between.
// After the first path, all paths will be joined with a dot instead of the path
// separator so that there is no level of directory after the first argument.
// Arguments must be convertible to string.
//
// Usage:
// string path = file::JoinPath("/tmp", dirname, filename);
template <typename... T>
std::string JoinPath(const T&... args) {
  return internal::JoinPathImpl({args...});
}

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_FILE_H_
