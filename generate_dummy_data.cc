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

// Tool to generate dummy data for the client and server in Private Join and
// Compute.

#include "gflags/gflags.h"

#include "glog/logging.h"
#include "data_util.h"

// Flags defining the size of data to generate for the client and server, bounds
// on the associated values, and where the write the outputs.
DEFINE_int64(server_data_size, 100,
             "Number of dummy identifiers in server database.");
DEFINE_int64(
    client_data_size, 100,
    "Number of dummy identifiers and associated values in client database.");
DEFINE_int64(intersection_size, 50,
             "Number of items in the intersection. Must be less than the "
             "server and client data sizes.");
DEFINE_int64(max_associated_value, 100,
             "Dummy associated values for the client will be between 0 and "
             "this. Must be nonnegative.");
DEFINE_string(server_data_file, "",
              "The file to which to write the server database.");
DEFINE_string(client_data_file, "",
              "The file to which to write the client database.");

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  auto maybe_dummy_data = private_join_and_compute::GenerateRandomDatabases(
      FLAGS_server_data_size, FLAGS_client_data_size, FLAGS_intersection_size,
      FLAGS_max_associated_value);

  if (!maybe_dummy_data.ok()) {
    std::cerr << "GenerateDummyData: Error generating the dummy data: "
              << maybe_dummy_data.status() << std::endl;
    return 1;
  }

  auto dummy_data = std::move(maybe_dummy_data.value());
  auto& server_identifiers = std::get<0>(dummy_data);
  auto& client_identifiers_and_associated_values = std::get<1>(dummy_data);
  int64_t intersection_sum = std::get<2>(dummy_data);

  auto server_write_status = private_join_and_compute::WriteServerDatasetToFile(
      server_identifiers, FLAGS_server_data_file);
  if (!server_write_status.ok()) {
    std::cerr << "GenerateDummyData: Error writing server dataset: "
              << server_write_status << std::endl;
    return 1;
  }

  auto client_write_status = private_join_and_compute::WriteClientDatasetToFile(
      client_identifiers_and_associated_values.first,
      client_identifiers_and_associated_values.second, FLAGS_client_data_file);
  if (!client_write_status.ok()) {
    std::cerr << "GenerateDummyData: Error writing client dataset: "
              << client_write_status << std::endl;
    return 1;
  }

  std::cout << "Generated Server dataset of size " << FLAGS_client_data_size
            << ", Client dataset of size " << FLAGS_client_data_size
            << std::endl;
  std::cout << "Intersection size = " << FLAGS_intersection_size << std::endl;
  std::cout << "Intersection sum = " << intersection_sum << std::endl;

  return 0;
}
