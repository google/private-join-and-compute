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

// Common implementations.

#include "private_join_and_compute/util/file.h"

#include <sstream>
#include <string>

namespace private_join_and_compute {
namespace internal {
namespace {

bool IsAbsolutePath(absl::string_view path) {
  return !path.empty() && path[0] == '/';
}

bool EndsWithSlash(absl::string_view path) {
  return !path.empty() && path[path.size() - 1] == '/';
}

}  // namespace

std::string JoinPathImpl(std::initializer_list<std::string> paths) {
  std::string joined_path;
  int size = paths.size();

  int counter = 1;
  for (auto it = paths.begin(); it != paths.end(); ++it, ++counter) {
    std::string path = *it;
    if (path.empty()) {
      continue;
    }

    if (it == paths.begin()) {
      joined_path += path;
      if (!EndsWithSlash(path)) {
        joined_path += "/";
      }
      continue;
    }

    if (EndsWithSlash(path)) {
      if (IsAbsolutePath(path)) {
        joined_path += path.substr(1, path.size() - 2);
      } else {
        joined_path += path.substr(0, path.size() - 1);
      }
    } else {
      if (IsAbsolutePath(path)) {
        joined_path += path.substr(1);
      } else {
        joined_path += path;
      }
    }
    if (counter != size) {
      joined_path += ".";
    }
  }
  return joined_path;
}

}  // namespace internal
}  // namespace private_join_and_compute
