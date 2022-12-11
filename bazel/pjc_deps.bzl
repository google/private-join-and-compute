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
            sha256 = "44fdfe7e9590e73ee3b92519c2f166b20301f3e0f8092fc6d03e540de95a3be4",
            strip_prefix = "glog-b33e3bad4c46c8a6345525fd822af355e5ef9446",
            urls = ["https://github.com/google/glog/archive/b33e3bad4c46c8a6345525fd822af355e5ef9446.zip"],
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
        git_repository(
            name = "com_google_absl",
            remote = "https://github.com/abseil/abseil-cpp.git",
            commit = "0f3bb466b868b523cf1dc9b2aaaed65c77b28862",
            shallow_since = "1603283562 -0400",
        )

    # gtest.
    if "com_github_google_googletest" not in native.existing_rules():
        git_repository(
            name = "com_github_google_googletest",
            commit = "703bd9caab50b139428cea1aaff9974ebee5742e",  # tag = "release-1.10.0"
            remote = "https://github.com/google/googletest.git",
            shallow_since = "1570114335 -0400",
        )

    # Protobuf
    if "com_google_protobuf" not in native.existing_rules():
        git_repository(
            name = "com_google_protobuf",
            remote = "https://github.com/protocolbuffers/protobuf.git",
            commit = "9647a7c2356a9529754c07235a2877ee676c2fd0",
            shallow_since = "1609366209 -0800",
        )
