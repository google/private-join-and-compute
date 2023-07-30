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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def pjc_deps():
    """Loads dependencies for the PJC library """

    if "boringssl" not in native.existing_rules():
        http_archive(
            name = "boringssl",
            sha256 = "d56ac3b83e7848e86a657f53c403a8f83f45d7eb2df22ffca5e8a25018af40d0",
            strip_prefix = "boringssl-2fbdc3bf0113d72e1bba77f9b135e513ccd0eb4b",
            urls = [
                "https://github.com/google/boringssl/archive/2fbdc3bf0113d72e1bba77f9b135e513ccd0eb4b.tar.gz",
            ],
        )

    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            sha256 = "f7c2cb2c5accdcbbbd5c0c59f241a988c0b1da2a3b7134b823c0bd613b1a6880",
            strip_prefix = "abseil-cpp-b971ac5250ea8de900eae9f95e06548d14cd95fe",
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/b971ac5250ea8de900eae9f95e06548d14cd95fe.zip",
            ],
        )

    # gtest.
    if "com_github_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_github_google_googletest",
            sha256 = "ad7fdba11ea011c1d925b3289cf4af2c66a352e18d4c7264392fead75e919363",
            strip_prefix = "googletest-1.13.0",
            urls = [
                "https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz",
            ],
        )

    # Protobuf
    if "com_google_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c",
            urls = [
                "https://github.com/protocolbuffers/protobuf/archive/f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c.tar.gz",
            ],
        )

    # Six (python compatibility)
    if "six" not in native.existing_rules():
        http_archive(
            name = "six",
            build_file = "@com_google_protobuf//:six.BUILD",
            sha256 = "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a",
            url = "https://pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz#md5=34eed507548117b2ab523ab14b2f8b55",
        )
