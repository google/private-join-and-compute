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

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "private_join_and_compute.h"

int main(int argc, char** argv) {
  std::vector<std::string> elements { "a", "b", "c" };
  std::vector<int64_t> values { 1, 2, 3 };

  ::private_join_and_compute::ClientSession session;
  ::private_join_and_compute::ClientResult result;
  int res = session.Run(1536, "0.0.0.0:10501", std::move(elements), std::move(values), &result);
  if (0 == res) {
    std::cout << "Client: Done, "
              << "size: " << result.intersection_size << ", "
              << "sum: " << result.intersection_sum
              << std::endl;
  }
}
