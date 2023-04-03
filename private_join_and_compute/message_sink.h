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

#ifndef PRIVATE_JOIN_AND_COMPUTE_MESSAGE_SINK_H_
#define PRIVATE_JOIN_AND_COMPUTE_MESSAGE_SINK_H_

#include <memory>

#include "private_join_and_compute/private_join_and_compute.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {

// An interface for message sinks.
template <typename T>
class MessageSink {
 public:
  virtual ~MessageSink() = default;

  // Subclasses should accept a message and process it appropriately.
  virtual Status Send(const T& message) = 0;

 protected:
  MessageSink() = default;
};

// A dummy message sink, that simply stores the last message received, and
// allows retrieval. Intended for testing.
template <typename T>
class DummyMessageSink : public MessageSink<T> {
 public:
  ~DummyMessageSink() override = default;

  // Simply copies the message.
  Status Send(const T& message) override {
    last_message_ = std::make_unique<T>(message);
    return OkStatus();
  }

  // Will fail if no message was received.
  const T& last_message() { return *last_message_; }

 private:
  std::unique_ptr<T> last_message_;
};

}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_MESSAGE_SINK_H_
