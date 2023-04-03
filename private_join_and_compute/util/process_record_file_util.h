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

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_UTIL_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_UTIL_H_

#include <algorithm>
#include <functional>
#include <future>  // NOLINT
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "private_join_and_compute/util/process_record_file_parameters.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/recordio.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute::util::process_file_util {

// Applies the function record_transformer() to all the records in input_file,
// and writes the resulting records to output_file, sorted by the key returned
// by the provided get_sorting_key_function. By default, records are sorted by
// their string representation.
// input_file must contain records of type InputFile.
// output_file contains records of type OutputFile.
// The files are processed in parallel using the number of threads specified by
// the ProcessRecordFileParameters.
// The file is processed in chunks of at most params.data_chunk_size values:
// read a chunk, apply function record_transformer() in parallel using
// params.thread_count threads, get the output values returned by each thread,
// and write them to file. Process the next chunk until there are no more values
// to read.
template <typename InputType, typename OutputType>
Status ProcessRecordFile(
    const std::function<StatusOr<OutputType>(InputType)>& record_transformer,
    const ProcessRecordFileParameters& params, absl::string_view input_file,
    absl::string_view output_file,
    const std::function<std::string(absl::string_view)>&
        get_sorting_key_function = [](absl::string_view raw_record) {
          return std::string(raw_record);
        }) {
  auto reader = std::unique_ptr<RecordReader>(RecordReader::GetRecordReader());
  RETURN_IF_ERROR(reader->Open(input_file));

  auto writer = ShardingWriter<std::string>::Get(get_sorting_key_function);
  writer->SetShardPrefix(output_file);

  std::string raw_record;
  size_t num_records_read = 0;
  // Process the file in chunks of at most data_chunk_size values: read a
  // chunk, process it in parallel using the number of available threads, get
  // the values returned by each thread, and write them to file.
  // Process the next chunk until there are no more values to read.
  ASSIGN_OR_RETURN(bool has_more, reader->HasMore());
  while (has_more) {
    // Read the next chunk to process in parallel.
    num_records_read = 0;
    std::vector<InputType> chunk;
    while (num_records_read < params.data_chunk_size && has_more) {
      RETURN_IF_ERROR(reader->Read(&raw_record));
      chunk.push_back(ProtoUtils::FromString<InputType>(raw_record));
      num_records_read++;
      ASSIGN_OR_RETURN(has_more, reader->HasMore());
    }

    // The max number of items each thread will process.
    size_t per_thread_size =
        (chunk.size() + params.thread_count - 1) / params.thread_count;

    // Stores the results of each thread.
    // Each thread processes a portion of chunk.
    std::vector<std::future<StatusOr<std::vector<OutputType>>>> futures;
    for (uint32_t j = 0; j < params.thread_count; j++) {
      size_t start = j * per_thread_size;
      size_t end = std::min((j + 1) * per_thread_size, num_records_read);
      // std::launch::async ensures multi-thread.
      futures.push_back(std::async(
          std::launch::async,
          [&chunk, start, end,
           record_transformer]() -> StatusOr<std::vector<OutputType>> {
            std::vector<OutputType> processes_chunk;
            for (size_t i = start; i < end; i++) {
              ASSIGN_OR_RETURN(auto processed_record,
                               record_transformer(chunk.at(i)));
              processes_chunk.push_back(std::move(processed_record));
            }
            return processes_chunk;
          }));
    }

    // Write the processed values returned by each thread to file.
    writer->SetShardPrefix(output_file);
    int index = 0;
    for (auto& future : futures) {
      index++;
      ASSIGN_OR_RETURN(auto records, future.get());
      for (const auto& record : records) {
        RETURN_IF_ERROR(writer->Write(ProtoUtils::ToString(record)));
      }
    }
  }
  RETURN_IF_ERROR(reader->Close());

  // Merge all the processed chunks into one output file and delete intermediate
  // chunk files.
  ASSIGN_OR_RETURN(auto shard_files, writer->Close());
  ShardMerger<std::string> merger;
  RETURN_IF_ERROR(
      merger.Merge(get_sorting_key_function, shard_files, output_file));
  RETURN_IF_ERROR(merger.Delete(shard_files));

  return OkStatus();
}

}  // namespace private_join_and_compute::util::process_file_util

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_UTIL_H_
