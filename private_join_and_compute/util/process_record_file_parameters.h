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

#ifndef PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_PARAMETERS_H_
#define PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_PARAMETERS_H_

#include <cstddef>
#include <cstdint>

namespace private_join_and_compute::util {

// Parameters needed by process_record_file.
struct ProcessRecordFileParameters {
  // The number of threads to use to parallelize the encryption operations.
  uint32_t thread_count = 8;

  // The maximum number of values to read in memory and encrypt at once.
  // Large data files will be encrypted in chunks to avoid running out of
  // memory.
  size_t data_chunk_size = 10'000'000;
};

}  // namespace private_join_and_compute::util

#endif  // PRIVATE_JOIN_AND_COMPUTE_UTIL_PROCESS_RECORD_FILE_PARAMETERS_H_
