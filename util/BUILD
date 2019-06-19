# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build file for util folder in open-source Private Join and Compute.

package(
    default_visibility = ["//visibility:public"],
    features = [
        "-layering_check",
        "-parse_headers",
    ],
)

cc_library(
    name = "status",
    srcs = glob(
        ["*.cc"],
    ),
    hdrs = glob(["*.h"]),
    deps = [
        "@com_github_glog_glog//:glog",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "status_includes",
    hdrs = ["status.inc"],
    deps = [
        ":status",
        "@com_google_protobuf//:protobuf_lite",
    ],
)
