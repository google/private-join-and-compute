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

load("@pip_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_library", "py_test")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "converters",
    srcs = [
        "converters.py",
    ],
    deps = [
        requirement("six"),
    ],
)

py_test(
    name = "converters_test",
    size = "small",
    srcs = ["converters_test.py"],
    deps = [
        ":converters",
    ],
)

py_library(
    name = "ssl_util",
    srcs = [
        "ssl_util.py",
    ],
    deps = [
        ":converters",
        ":supported_hashes",
        requirement("six"),
        requirement("absl-py"),
    ],
)

py_library(
    name = "supported_curves",
    srcs = [
        "supported_curves.py",
    ],
)

py_library(
    name = "supported_hashes",
    srcs = [
        "supported_hashes.py",
    ],
)

py_test(
    name = "ssl_util_test",
    size = "small",
    srcs = ["ssl_util_test.py"],
    deps = [
        ":ssl_util",
        requirement("absl-py"),
    ],
)

py_library(
    name = "elliptic_curve",
    srcs = [
        "elliptic_curve.py",
    ],
    deps = [
        ":converters",
        ":ssl_util",
        ":supported_curves",
        ":supported_hashes",
        requirement("six"),
    ],
)

py_test(
    name = "elliptic_curve_test",
    size = "small",
    srcs = ["elliptic_curve_test.py"],
    deps = [
        ":converters",
        ":elliptic_curve",
        ":ssl_util",
        ":supported_curves",
        ":supported_hashes",
    ],
)
