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

# Description:
#   Contains libraries for openssl big num operations.
load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")
load("@pip_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_library", "py_test")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "ec_cipher",
    srcs = [
        "ec_cipher.py",
    ],
    deps = [
        "//private_join_and_compute/py/crypto_util:elliptic_curve",
        "//private_join_and_compute/py/crypto_util:supported_hashes",
    ],
)

py_test(
    name = "ec_cipher_test",
    size = "small",
    srcs = ["ec_cipher_test.py"],
    deps = [
        ":ec_cipher",
        "//private_join_and_compute/py/crypto_util:supported_curves",
        "//private_join_and_compute/py/crypto_util:supported_hashes",
    ],
)
