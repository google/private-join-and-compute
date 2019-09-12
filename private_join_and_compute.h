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

#ifndef OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_H_
#define OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_H_

#include <string>
#include <vector>

namespace private_join_and_compute {

struct ClientResult {
  int64_t intersection_size;
  uint64_t intersection_sum;
};

class ClientSession {
 public:
  ClientSession();

  ~ClientSession();

  int Run(int32_t paillier_modulus_size,
          std::string port,
          const std::vector<std::string>& elements,
          const std::vector<int64_t>& values,
          ClientResult* result);
};

class ServerSession {
 public:
  ServerSession();

  ~ServerSession();

  int Run(std::string port,
          const std::vector<std::string>& elements);
  
  int RunAsync(std::string port,
               const std::vector<std::string>& elements);

  int Wait();

 private:
  class ServerSessionState;
  std::unique_ptr<ServerSessionState> _state;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_H_
