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

// Defines file operations.
// RecordWriter generates output records that are binary data preceded with a
// Varint that explains the size of the records. The records provided to
// RecordWriter can be arbitrary binary data, but usually they will be
// serialized protobufs.
//
// RecordReader reads files written in the above format, and is also compatible
// with files written using the Java version of parseDelimitedFrom and
// writeDelimitedTo.
//
// LineWriter writes single lines to the output file. LineReader reads single
// lines from the input file.
//
// Note that all classes except ShardingWriter are not thread-safe: concurrent
// accesses must be protected by mutexes.

#ifndef PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_RECORDIO_H_
#define PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_RECORDIO_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "private_join_and_compute/util/file.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// Interface for reading a single file.
class RecordReader {
 public:
  virtual ~RecordReader() = default;

  // RecordReader is neither copyable nor movable.
  RecordReader(const RecordReader&) = delete;
  RecordReader& operator=(const RecordReader&) = delete;

  // Opens the given file for reading.
  virtual Status Open(absl::string_view file_name) = 0;

  // Closes any file object created via calling SingleFileReader::Open
  virtual Status Close() = 0;

  // Returns true if there are more records in the file to be read.
  virtual StatusOr<bool> HasMore() = 0;

  // Reads a record from the file (line or binary record).
  virtual Status Read(std::string* record) = 0;

  // Returns a RecordReader for reading files line by line.
  // Caller takes the ownership.
  static RecordReader* GetLineReader();

  // Returns a RecordReader for reading files in a record format compatible with
  // RecordWriter below.
  // Caller takes the ownership.
  static RecordReader* GetRecordReader();

  // Test only.
  static RecordReader* GetLineReader(File* file);
  static RecordReader* GetRecordReader(File* file);

 protected:
  RecordReader() = default;
};

// Reads records one at a time in ascending order from multiple files, assuming
// each file stores records in ascending order. This class does the merge step
// for the external sorting. Templates T supported are string and int64.
template <typename T>
class MultiSortedReader {
 public:
  virtual ~MultiSortedReader() = default;

  // MultiSortedReader is neither copyable nor movable.
  MultiSortedReader(const MultiSortedReader&) = delete;
  MultiSortedReader& operator=(const MultiSortedReader&) = delete;

  // Opens the files generated with RecordWriterInterface. Records in each file
  // are assumed to be sorted beforehand.
  virtual Status Open(const std::vector<std::string>& filenames) = 0;

  // Same as Open above but also accepts a key function that is used to convert
  // a string record into a value of type T, used when comparing the records.
  // Records will be read from the file heads in ascending order of "key".
  virtual Status Open(const std::vector<std::string>& filenames,
                      const std::function<T(absl::string_view)>& key) = 0;

  // Closes the file streams.
  virtual Status Close() = 0;

  // Returns true if there are more records in the file to be read.
  virtual StatusOr<bool> HasMore() = 0;

  // Reads a record data into <code>data</code> in ascending order.
  // Erases the <code>data</code> before writing to it.
  virtual Status Read(std::string* data) = 0;

  // Same as Read(string* data) but this also puts the index of the file
  // where the data has been read from if index is not nullptr.
  // Erases the <code>data</code> before writing to it.
  virtual Status Read(std::string* data, int* index) = 0;

  // Returns a MultiSortedReader.
  // Caller takes the ownership.
  static MultiSortedReader<T>* Get();

  // Test only.
  static MultiSortedReader* Get(
      const std::function<RecordReader*()>& get_reader);

 protected:
  MultiSortedReader() = default;
};

class RecordWriter {
 public:
  virtual ~RecordWriter() = default;

  // RecordWriter is neither copyable nor movable.
  RecordWriter(const RecordWriter&) = delete;
  RecordWriter& operator=(const RecordWriter&) = delete;

  // Opens the given file for writing records.
  virtual Status Open(absl::string_view file_name) = 0;

  // Closes the file stream and returns true if successful.
  virtual Status Close() = 0;

  // Writes <code>raw_data</code> into the file as-is, with a delimiter
  // specifying the data size.
  virtual Status Write(absl::string_view raw_data) = 0;

  // Returns a RecordWriter.
  // Caller takes the ownership.
  static RecordWriter* Get();

  // Test only.
  static RecordWriter* Get(File* file);

 protected:
  RecordWriter() = default;
};

class LineWriter {
 public:
  virtual ~LineWriter() = default;

  // LineWriter is neither copyable nor movable.
  LineWriter(const LineWriter&) = delete;
  LineWriter& operator=(const LineWriter&) = delete;

  // Opens the given file for writing lines.
  virtual Status Open(absl::string_view file_name) = 0;

  // Closes the file stream and returns OkStatus if successful.
  virtual Status Close() = 0;

  // Writes <code>line</code> into the file, with a trailing newline.
  // Returns OkStatus if the write operation was successful.
  virtual Status Write(absl::string_view line) = 0;

  // Returns a RecordWriter.
  // Caller takes the ownership.
  static LineWriter* Get();

  // Test only.
  static LineWriter* Get(File* file);

 protected:
  LineWriter() = default;
};

// Writes Records to shard files, with each shard file internally sorted based
// on the supplied get_key method.
//
// This class is thread-safe.
template <typename T>
class ShardingWriter {
 public:
  virtual ~ShardingWriter() = default;

  // ShardingWriter is neither copyable nor copy-assignable.
  ShardingWriter(const ShardingWriter&) = delete;
  ShardingWriter& operator=(const ShardingWriter&) = delete;

  // Shards will be created with the supplied prefix. Must be called before
  // Write.
  virtual void SetShardPrefix(absl::string_view shard_prefix) = 0;

  // Clears the remaining cache, and returns the list of all shard files that
  // were written since the last call to SetShardPrefix. Caller is responsible
  // for merging and deleting shards.
  //
  // Returns InternalError if clearing the remaining cache fails.
  virtual StatusOr<std::vector<std::string>> Close() = 0;

  // Writes the supplied str into the file.
  // Implementations need not actually write the record on each call. Rather,
  // they may cache records until max_bytes records have been cached, at which
  // point they may sort the cache and write it to a shard file.
  //
  // Implementations must return InternalError if writing the cache fails, or
  // if the shard prefix has not been set.
  virtual Status Write(absl::string_view raw_data) = 0;

  // Returns a ShardingWriter that uses the supplied key to compare records.
  // @param max_bytes: denotes the maximum size of each shard to write.
  static std::unique_ptr<ShardingWriter> Get(
      const std::function<T(absl::string_view)>& get_key,
      int32_t max_bytes = 209715200 /* 200MB */);

  // Test only.
  static std::unique_ptr<ShardingWriter> Get(
      const std::function<T(absl::string_view)>& get_key, int32_t max_bytes,
      std::unique_ptr<RecordWriter> record_writer);

 protected:
  ShardingWriter() = default;
};

// Utility class to allow merging of sorted shards, and deleting of shards.
template <typename T>
class ShardMerger {
 public:
  explicit ShardMerger(std::unique_ptr<MultiSortedReader<T>> multi_reader =
                           absl::WrapUnique(MultiSortedReader<T>::Get()),
                       std::unique_ptr<RecordWriter> writer =
                           absl::WrapUnique(RecordWriter::Get()));

  // Merges the supplied shards into a single output file, using the supplied
  // key.
  Status Merge(const std::function<T(absl::string_view)>& get_key,
               const std::vector<std::string>& shard_files,
               absl::string_view output_file);

  // Deletes the supplied shard files.
  Status Delete(std::vector<std::string> shard_files);

 private:
  std::unique_ptr<MultiSortedReader<T>> multi_reader_;
  std::unique_ptr<RecordWriter> writer_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_INTERNAL_UTIL_RECORDIO_H_
