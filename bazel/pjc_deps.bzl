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

""" Dependencies needed to compile and test the PJC library """

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def pjc_deps():
    """Loads dependencies need to compile and test the PJC library."""
    if "com_github_google_glog" not in native.existing_rules():
        http_archive(
            name = "com_github_google_glog",
            sha256 = "42c7395b26f1aa2157015b7d7b811b799c9c477147f4239410bde48901f009c5",
            strip_prefix = "glog-c18db3903b9f0abd80ae740fde94f7e32aa40b92",
            urls = ["https://github.com/google/glog/archive/c18db3903b9f0abd80ae740fde94f7e32aa40b92.zip"],
        )

    if "com_github_gflags_gflags" not in native.existing_rules():
        # gflags
        # Needed for glog
        http_archive(
            name = "com_github_gflags_gflags",
            sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
            strip_prefix = "gflags-2.2.2",
            urls = [
                "https://mirror.bazel.build/github.com/gflags/gflags/archive/v2.2.2.tar.gz",
                "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
            ],
        )

    # Abseil C++ libraries
    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            sha256 = "31b0b6fe3f14875a27c48d5775d05e157bab233065f7c55f0e1f4991c5e95840",
            strip_prefix = "abseil-cpp-522606b7fae37836c138e83f6eec0eabb9947dc0",
            url = "https://github.com/abseil/abseil-cpp/archive/522606b7fae37836c138e83f6eec0eabb9947dc0.zip",
        )

    # gtest.
    if "com_github_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_google_googletest",
            sha256 = "81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2",
            strip_prefix = "googletest-release-1.12.1",
            url = "https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
        )

    # Protobuf
    if "com_github_protocolbuffers_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_github_protocolbuffers_protobuf",
            sha256 = "930c2c3b5ecc6c9c12615cf5ad93f1cd6e12d0aba862b572e076259970ac3a53",
            strip_prefix = "protobuf-3.21.12",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v3.21.12.tar.gz"],
        )
