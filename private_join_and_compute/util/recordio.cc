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

#include <algorithm>
#include <functional>
#include <list>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "private_join_and_compute/util/status.inc"
#include "src/google/protobuf/io/coded_stream.h"
#include "src/google/protobuf/io/zero_copy_stream_impl_lite.h"

namespace private_join_and_compute {

namespace {

// Max. size of a Varint32 (from proto references).
const uint32_t kMaxVarint32Size = 5;

// Tries to read a Varint32 from the front of a given file. Returns false if the
// reading fails.
StatusOr<uint32_t> ExtractVarint32(File* file) {
  // Keep reading a single character until one is found such that the top bit is
  // 0;
  std::string bytes_read = "";

  size_t current_byte = 0;
  ASSIGN_OR_RETURN(auto has_more, file->HasMore());
  while (current_byte < kMaxVarint32Size && has_more) {
    auto maybe_last_byte = file->Read(1);
    if (!maybe_last_byte.ok()) {
      return maybe_last_byte.status();
    }

    bytes_read += maybe_last_byte.value();
    if (!(bytes_read.data()[current_byte] & 0x80)) {
      break;
    }
    current_byte++;
    // If we read the max number of bits and never found a "terminating" byte,
    // return false.
    if (current_byte >= kMaxVarint32Size) {
      return InvalidArgumentError(
          "ExtractVarint32: Failed to extract a Varint after reading max "
          "number "
          "of bytes.");
    }
    ASSIGN_OR_RETURN(has_more, file->HasMore());
  }

  google::protobuf::io::ArrayInputStream arrayInputStream(bytes_read.data(),
                                                          bytes_read.size());
  google::protobuf::io::CodedInputStream codedInputStream(&arrayInputStream);
  uint32_t result;
  codedInputStream.ReadVarint32(&result);

  return result;
}

// Reads records from a file one at a time.
class RecordReaderImpl : public RecordReader {
 public:
  explicit RecordReaderImpl(File* file) : RecordReader(), in_(file) {}

  Status Open(absl::string_view filename) final {
    return in_->Open(filename, "r");
  }

  Status Close() final { return in_->Close(); }

  StatusOr<bool> HasMore() final {
    auto status_or_has_more = in_->HasMore();
    if (!status_or_has_more.ok()) {
      LOG(ERROR) << status_or_has_more.status();
    }
    return status_or_has_more;
  }

  Status Read(std::string* raw_data) final {
    raw_data->erase();
    auto maybe_record_size = ExtractVarint32(in_.get());
    if (!maybe_record_size.ok()) {
      LOG(ERROR) << "RecordReader::Read: Couldn't read record size: "
                 << maybe_record_size.status();
      return maybe_record_size.status();
    }
    uint32_t record_size = maybe_record_size.value();

    auto status_or_data = in_->Read(record_size);
    if (!status_or_data.ok()) {
      LOG(ERROR) << status_or_data.status();
      return status_or_data.status();
    }

    raw_data->append(status_or_data.value());
    return OkStatus();
  }

 private:
  std::unique_ptr<File> in_;
};

// Reads lines from a file one at a time.
class LineReader : public RecordReader {
 public:
  explicit LineReader(File* file) : RecordReader(), in_(file) {}

  Status Open(absl::string_view filename) final {
    return in_->Open(filename, "r");
  }

  Status Close() final { return in_->Close(); }

  StatusOr<bool> HasMore() final { return in_->HasMore(); }

  Status Read(std::string* line) final {
    line->erase();
    auto status_or_line = in_->ReadLine();
    if (!status_or_line.ok()) {
      LOG(ERROR) << status_or_line.status();
      return status_or_line.status();
    }
    line->append(status_or_line.value());
    return OkStatus();
  }

 private:
  std::unique_ptr<File> in_;
};

template <typename T>
class MultiSortedReaderImpl : public MultiSortedReader<T> {
 public:
  explicit MultiSortedReaderImpl(
      const std::function<RecordReader*()>& get_reader,
      std::unique_ptr<std::function<T(absl::string_view)>> default_key =
          nullptr)
      : MultiSortedReader<T>(),
        get_reader_(get_reader),
        default_key_(std::move(default_key)),
        key_(nullptr) {}

  Status Open(const std::vector<std::string>& filenames) override {
    if (default_key_ == nullptr) {
      return InvalidArgumentError("The sorting key is null.");
    }
    return Open(filenames, *default_key_);
  }

  Status Open(const std::vector<std::string>& filenames,
              const std::function<T(absl::string_view)>& key) override {
    if (!readers_.empty()) {
      return InternalError("There are files not closed, call Close() first.");
    }
    key_ = std::make_unique<std::function<T(absl::string_view)>>(key);
    for (size_t i = 0; i < filenames.size(); ++i) {
      this->readers_.push_back(std::unique_ptr<RecordReader>(get_reader_()));
      auto open_status = this->readers_.back()->Open(filenames[i]);
      if (!open_status.ok()) {
        // Try to close the opened ones.
        for (int j = i - 1; j >= 0; --j) {
          // If closing fails as well, then any call to Open will fail as well
          // since some of the files will remain opened.
          auto status = this->readers_[j]->Close();
          if (!status.ok()) {
            LOG(ERROR) << "Error closing file " << status;
          }
          this->readers_.pop_back();
        }
        return open_status;
      }
    }
    return OkStatus();
  }

  Status Close() override {
    Status status = OkStatus();
    bool ret_val =
        std::all_of(readers_.begin(), readers_.end(),
                    [&status](std::unique_ptr<RecordReader>& reader) {
                      Status close_status = reader->Close();
                      if (!close_status.ok()) {
                        status = close_status;
                        return false;
                      } else {
                        return true;
                      }
                    });
    if (ret_val) {
      readers_ = std::vector<std::unique_ptr<RecordReader>>();
      min_heap_ = std::priority_queue<HeapData, std::vector<HeapData>,
                                      HeapDataGreater>();
    }
    return status;
  }

  StatusOr<bool> HasMore() override {
    if (!min_heap_.empty()) {
      return true;
    }
    Status status = OkStatus();
    for (const auto& reader : readers_) {
      auto status_or_has_more = reader->HasMore();
      if (status_or_has_more.ok()) {
        if (status_or_has_more.value()) {
          return true;
        }
      } else {
        status = status_or_has_more.status();
      }
    }
    if (status.ok()) {
      // None of the readers has more.
      return false;
    }
    return status;
  }

  Status Read(std::string* data) override { return Read(data, nullptr); }

  Status Read(std::string* data, int* index) override {
    if (min_heap_.empty()) {
      for (size_t i = 0; i < readers_.size(); ++i) {
        RETURN_IF_ERROR(this->ReadHeapDataFromReader(i));
      }
    }
    HeapData ret_data = min_heap_.top();
    data->assign(ret_data.data);
    if (index != nullptr) *index = ret_data.index;
    min_heap_.pop();
    return this->ReadHeapDataFromReader(ret_data.index);
  }

 private:
  Status ReadHeapDataFromReader(int index) {
    std::string data;
    auto status_or_has_more = readers_[index]->HasMore();
    if (!status_or_has_more.ok()) {
      return status_or_has_more.status();
    }
    if (status_or_has_more.value()) {
      RETURN_IF_ERROR(readers_[index]->Read(&data));
      HeapData heap_data;
      heap_data.key = (*key_)(data);
      heap_data.data = data;
      heap_data.index = index;
      min_heap_.push(heap_data);
    }
    return OkStatus();
  }

  struct HeapData {
    T key;
    std::string data;
    int index;
  };

  struct HeapDataGreater {
    bool operator()(const HeapData& lhs, const HeapData& rhs) const {
      return lhs.key > rhs.key;
    }
  };

  const std::function<RecordReader*()> get_reader_;
  std::unique_ptr<std::function<T(absl::string_view)>> default_key_;
  std::unique_ptr<std::function<T(absl::string_view)>> key_;
  std::vector<std::unique_ptr<RecordReader>> readers_;
  std::priority_queue<HeapData, std::vector<HeapData>, HeapDataGreater>
      min_heap_;
};

// Writes records to a file one at a time.
class RecordWriterImpl : public RecordWriter {
 public:
  explicit RecordWriterImpl(File* file) : RecordWriter(), out_(file) {}

  Status Open(absl::string_view filename) final {
    return out_->Open(filename, "w");
  }

  Status Close() final { return out_->Close(); }

  Status Write(absl::string_view raw_data) final {
    std::string delimited_output;
    auto string_output =
        std::make_unique<google::protobuf::io::StringOutputStream>(
            &delimited_output);
    auto coded_output =
        std::make_unique<google::protobuf::io::CodedOutputStream>(
            string_output.get());

    // Write the delimited output.
    coded_output->WriteVarint32(raw_data.size());
    coded_output->WriteString(std::string(raw_data));

    // Force the serialization, which makes delimited_output safe to read.
    coded_output = nullptr;
    string_output = nullptr;

    return out_->Write(delimited_output, delimited_output.size());
  }

 private:
  std::unique_ptr<File> out_;
};

// Writes lines to a file one at a time.
class LineWriterImpl : public LineWriter {
 public:
  explicit LineWriterImpl(File* file) : LineWriter(), out_(file) {}

  Status Open(absl::string_view filename) final {
    return out_->Open(filename, "w");
  }

  Status Close() final { return out_->Close(); }

  Status Write(absl::string_view line) final {
    RETURN_IF_ERROR(out_->Write(line.data(), line.size()));
    return out_->Write("\n", 1);
  }

 private:
  std::unique_ptr<File> out_;
};

}  // namespace

RecordReader* RecordReader::GetLineReader() {
  return RecordReader::GetLineReader(File::GetFile());
}

RecordReader* RecordReader::GetLineReader(File* file) {
  return new LineReader(file);
}

RecordReader* RecordReader::GetRecordReader() {
  return RecordReader::GetRecordReader(File::GetFile());
}

RecordReader* RecordReader::GetRecordReader(File* file) {
  return new RecordReaderImpl(file);
}

RecordWriter* RecordWriter::Get() { return RecordWriter::Get(File::GetFile()); }

RecordWriter* RecordWriter::Get(File* file) {
  return new RecordWriterImpl(file);
}

LineWriter* LineWriter::Get() { return LineWriter::Get(File::GetFile()); }

LineWriter* LineWriter::Get(File* file) { return new LineWriterImpl(file); }

template <typename T>
MultiSortedReader<T>* MultiSortedReader<T>::Get() {
  return MultiSortedReader<T>::Get(
      []() { return RecordReader::GetRecordReader(); });
}

template <>
MultiSortedReader<std::string>* MultiSortedReader<std::string>::Get(
    const std::function<RecordReader*()>& get_reader) {
  return new MultiSortedReaderImpl<std::string>(
      get_reader,
      std::make_unique<std::function<std::string(absl::string_view)>>(
          [](absl::string_view s) { return std::string(s); }));
}

template <>
MultiSortedReader<int64_t>* MultiSortedReader<int64_t>::Get(
    const std::function<RecordReader*()>& get_reader) {
  return new MultiSortedReaderImpl<int64_t>(
      get_reader, std::make_unique<std::function<int64_t(absl::string_view)>>(
                      [](absl::string_view s) { return 0; }));
}

template class MultiSortedReader<int64_t>;
template class MultiSortedReader<std::string>;

namespace {

std::string GetFilename(absl::string_view prefix, int32_t idx) {
  return absl::StrCat(prefix, idx);
}

template <typename T>
class ShardingWriterImpl : public ShardingWriter<T> {
 public:
  static Status AlreadyUnhealthyError() {
    return InternalError("ShardingWriter: Already unhealthy.");
  }

  explicit ShardingWriterImpl(
      const std::function<T(absl::string_view)>& get_key,
      int32_t max_bytes = 209715200, /* 200MB */
      std::unique_ptr<RecordWriter> record_writer =
          absl::WrapUnique(RecordWriter::Get()))
      : get_key_(get_key),
        record_writer_(std::move(record_writer)),
        max_bytes_(max_bytes),
        cache_(),
        bytes_written_(0),
        current_file_idx_(0),
        shard_files_(),
        healthy_(true),
        open_(false) {}

  void SetShardPrefix(absl::string_view shard_prefix) override {
    absl::MutexLock lock(&mutex_);
    open_ = true;
    fnames_prefix_ = std::string(shard_prefix);
    current_fname_ = GetFilename(fnames_prefix_, current_file_idx_);
  }

  StatusOr<std::vector<std::string>> Close() override {
    absl::MutexLock lock(&mutex_);

    auto retval = TryClose();

    // Guarantee that the state is reset, even if TryClose fails.
    fnames_prefix_ = "";
    current_fname_ = "";
    healthy_ = true;
    cache_.clear();
    bytes_written_ = 0;
    shard_files_.clear();
    current_file_idx_ = 0;
    open_ = false;

    return retval;
  }

  // Writes the supplied Record into the file.
  // Returns true if the write operation was successful.
  Status Write(absl::string_view raw_record) override {
    absl::MutexLock lock(&mutex_);
    if (!open_) {
      return InternalError("Must call SetShardPrefix before calling Write.");
    }
    if (!healthy_) {
      return AlreadyUnhealthyError();
    }
    if (bytes_written_ > max_bytes_) {
      RETURN_IF_ERROR(WriteCacheToFile());
    }
    bytes_written_ += raw_record.size();
    cache_.push_back(std::string(raw_record));
    return OkStatus();
  }

 private:
  Status WriteCacheToFile() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    if (!healthy_) return AlreadyUnhealthyError();
    if (cache_.empty()) return OkStatus();
    cache_.sort([this](absl::string_view r1, absl::string_view r2) {
      return get_key_(r1) < get_key_(r2);
    });
    if (!record_writer_->Open(current_fname_).ok()) {
      healthy_ = false;
      return InternalError(
          absl::StrCat("Cannot open ", current_fname_, " for writing."));
    }
    Status status = absl::OkStatus();
    for (absl::string_view r : cache_) {
      if (!record_writer_->Write(r).ok()) {
        healthy_ = false;
        status = InternalError(
            absl::StrCat("Cannot write record ", r, " to ", current_fname_));

        break;
      }
    }
    if (!record_writer_->Close().ok()) {
      if (status.ok()) {
        status =
            InternalError(absl::StrCat("Cannot close ", current_fname_, "."));
      } else {
        // Preserve the old status message.
        LOG(WARNING) << "Cannot close " << current_fname_;
      }
    }

    shard_files_.push_back(current_fname_);
    cache_.clear();
    bytes_written_ = 0;
    ++current_file_idx_;
    current_fname_ = GetFilename(fnames_prefix_, current_file_idx_);
    return status;
  }

  StatusOr<std::vector<std::string>> TryClose()
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    if (!open_) {
      return InternalError("Must call SetShardPrefix before calling Close.");
    }
    RETURN_IF_ERROR(WriteCacheToFile());

    return {shard_files_};
  }

  absl::Mutex mutex_;
  std::function<T(absl::string_view)> get_key_;
  std::unique_ptr<RecordWriter> record_writer_ ABSL_GUARDED_BY(mutex_);
  std::string fnames_prefix_ ABSL_GUARDED_BY(mutex_);
  const int32_t max_bytes_ ABSL_GUARDED_BY(mutex_);
  std::list<std::string> cache_ ABSL_GUARDED_BY(mutex_);
  int32_t bytes_written_ ABSL_GUARDED_BY(mutex_);
  int32_t current_file_idx_ ABSL_GUARDED_BY(mutex_);
  std::string current_fname_ ABSL_GUARDED_BY(mutex_);
  std::vector<std::string> shard_files_ ABSL_GUARDED_BY(mutex_);
  bool healthy_ ABSL_GUARDED_BY(mutex_);
  bool open_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace

template <typename T>
std::unique_ptr<ShardingWriter<T>> ShardingWriter<T>::Get(
    const std::function<T(absl::string_view)>& get_key, int32_t max_bytes) {
  return std::make_unique<ShardingWriterImpl<T>>(get_key, max_bytes);
}

// Test only.
template <typename T>
std::unique_ptr<ShardingWriter<T>> ShardingWriter<T>::Get(
    const std::function<T(absl::string_view)>& get_key, int32_t max_bytes,
    std::unique_ptr<RecordWriter> record_writer) {
  return std::make_unique<ShardingWriterImpl<T>>(get_key, max_bytes,
                                                 std::move(record_writer));
}

template class ShardingWriter<int64_t>;
template class ShardingWriter<std::string>;

template <typename T>
ShardMerger<T>::ShardMerger(std::unique_ptr<MultiSortedReader<T>> multi_reader,
                            std::unique_ptr<RecordWriter> writer)
    : multi_reader_(std::move(multi_reader)), writer_(std::move(writer)) {}

template <typename T>
Status ShardMerger<T>::Merge(const std::function<T(absl::string_view)>& get_key,
                             const std::vector<std::string>& shard_files,
                             absl::string_view output_file) {
  if (shard_files.empty()) {
    // Create an empty output file.
    RETURN_IF_ERROR(writer_->Open(output_file));
    RETURN_IF_ERROR(writer_->Close());
  }

  // Multi-sorted-read all shards, and write the results to the supplied file.
  std::vector<std::string> converted_shard_files;
  converted_shard_files.reserve(shard_files.size());
  for (const auto& filename : shard_files) {
    converted_shard_files.push_back(filename);
  }

  RETURN_IF_ERROR(multi_reader_->Open(converted_shard_files, get_key));

  RETURN_IF_ERROR(writer_->Open(output_file));

  for (std::string record; multi_reader_->HasMore().value();) {
    RETURN_IF_ERROR(multi_reader_->Read(&record));
    RETURN_IF_ERROR(writer_->Write(record));
  }
  RETURN_IF_ERROR(writer_->Close());

  RETURN_IF_ERROR(multi_reader_->Close());

  return OkStatus();
}

template <typename T>
Status ShardMerger<T>::Delete(std::vector<std::string> shard_files) {
  for (const auto& filename : shard_files) {
    RETURN_IF_ERROR(DeleteFile(filename));
  }

  return OkStatus();
}

template class ShardMerger<int64_t>;
template class ShardMerger<std::string>;

}  // namespace private_join_and_compute
