# Copyright 2019 Google LLC.
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

"""WORKSPACE file for Private Join and Compute."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:pjc_deps.bzl", "pjc_deps")

# gRPC
# must be included separately, since we need to load transitive deps of grpc.
http_archive(
    name = "com_github_grpc_grpc",
    sha256 = "acf247ec3a52edaee5dee28644a4e485c5e5badf46bdb24a80ca1d76cb8f1174",
    strip_prefix = "grpc-1.37.1",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.37.1.tar.gz",
    ],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()

pjc_deps()
