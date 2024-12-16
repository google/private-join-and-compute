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
            strip_prefix = "boringssl-fcef13a49852397a0d39c00be8d7bc2ba1ab6fb9",
            integrity = "sha256-/0NFA2qR7hqV35nTIsx2KPwNNsMg7lZEoiNfkN3uuKg=",
            urls = [
                "https://github.com/google/boringssl/archive/fcef13a49852397a0d39c00be8d7bc2ba1ab6fb9.tar.gz",
            ],
        )

    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-4447c7562e3bc702ade25105912dce503f0c4010",
            integrity = "sha256-2DQq13qp4WEDxIa2FUYMJKaVofBM23YOsC/veA35l1k=",
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/4447c7562e3bc702ade25105912dce503f0c4010.zip",
            ],
        )

    # gtest.
    if "com_github_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_github_google_googletest",
            strip_prefix = "googletest-1.15.2",
            integrity = "sha256-e0K01u1IgQxTYsJloX+uvpDcI3PIheUhZDnTeSfwKSY=",
            urls = [
                "https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz",
            ],
        )

    # Protobuf
    if "com_google_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-5fda5abda3dee5f7a102c85860594bff8d8610bd",
            integrity = "sha256-jY+vJ/71Ul+pFEvu8szQcqOwEyW/xytoKkB9kbYyEvI=",
            urls = [
                "https://github.com/protocolbuffers/protobuf/archive/5fda5abda3dee5f7a102c85860594bff8d8610bd.tar.gz",
            ],
        )

    # Six (python compatibility)
    if "six" not in native.existing_rules():
        http_archive(
            name = "six",
            build_file = "@com_google_protobuf//:six.BUILD",
            url = "hhttps://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz",
        )
