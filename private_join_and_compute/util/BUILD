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

# Build file for util folder in open-source Private Join and Compute.

load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(
    default_visibility = ["//visibility:public"],
    features = [
        "-layering_check",
        "-parse_headers",
    ],
)

cc_library(
    name = "status_includes",
    hdrs = [
        "status.inc",
        "status_macros.h",
    ],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "status_testing_includes",
    hdrs = [
        "status_matchers.h",
        "status_testing.h",
        "status_testing.inc",
    ],
    deps = [
        ":status_includes",
        "@com_github_google_googletest//:gtest",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "file",
    srcs = [
        "file.cc",
        "file_posix.cc",
    ],
    hdrs = [
        "file.h",
    ],
    deps = [
        ":status_includes",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "file_test",
    size = "small",
    srcs = [
        "file_test.cc",
    ],
    deps = [
        ":file",
        "@com_github_google_googletest//:gtest_main",
    ],
)

grpc_proto_library(
    name = "file_test_proto",
    srcs = ["file_test.proto"],
)

cc_library(
    name = "proto_util",
    hdrs = ["proto_util.h"],
    deps = [
        ":recordio",
        ":status_includes",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "proto_util_test",
    size = "medium",
    srcs = ["proto_util_test.cc"],
    deps = [
        ":file_test_proto",
        ":proto_util",
        ":status_testing_includes",
        "@com_github_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "recordio",
    srcs = [
        "recordio.cc",
    ],
    hdrs = ["recordio.h"],
    deps = [
        ":file",
        ":status_includes",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "recordio_test",
    srcs = ["recordio_test.cc"],
    deps = [
        ":file_test_proto",
        ":proto_util",
        ":recordio",
        ":status_includes",
        ":status_testing_includes",
        "//private_join_and_compute/crypto:bn_util",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "process_record_file_parameters",
    hdrs = ["process_record_file_parameters.h"],
    deps = [
        "//private_join_and_compute/crypto:ec_commutative_cipher",
        "//private_join_and_compute/crypto:openssl_includes",
    ],
)

cc_library(
    name = "process_record_file_util",
    hdrs = ["process_record_file_util.h"],
    deps = [
        ":process_record_file_parameters",
        ":proto_util",
        ":recordio",
        ":status_includes",
        "@com_google_absl//absl/strings",
    ],
)

grpc_proto_library(
    name = "test_proto",
    srcs = ["test.proto"],
)

cc_test(
    name = "process_record_file_util_test",
    srcs = ["process_record_file_util_test.cc"],
    deps = [
        ":process_record_file_parameters",
        ":process_record_file_util",
        ":proto_util",
        ":status_testing_includes",
        ":test_proto",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "elgamal_proto_util",
    srcs = ["elgamal_proto_util.cc"],
    hdrs = ["elgamal_proto_util.h"],
    deps = [
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:elgamal",
        "//private_join_and_compute/crypto:elgamal_proto",
    ],
)

cc_library(
    name = "elgamal_key_util",
    srcs = ["elgamal_key_util.cc"],
    hdrs = ["elgamal_key_util.h"],
    deps = [
        ":elgamal_proto_util",
        ":proto_util",
        ":recordio",
        ":status_includes",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:elgamal_proto",
    ],
)

cc_library(
    name = "ec_key_util",
    srcs = ["ec_key_util.cc"],
    hdrs = ["ec_key_util.h"],
    deps = [
        ":proto_util",
        ":recordio",
        ":status_includes",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_key_proto",
        "//private_join_and_compute/crypto:ec_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "elgamal_proto_util_test",
    srcs = ["elgamal_proto_util_test.cc"],
    deps = [
        ":elgamal_proto_util",
        ":status_testing_includes",
        "@com_github_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "elgamal_key_util_test",
    srcs = ["elgamal_key_util_test.cc"],
    deps = [
        ":elgamal_key_util",
        ":elgamal_proto_util",
        ":proto_util",
        ":status_testing_includes",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:elgamal",
        "//private_join_and_compute/crypto:elgamal_proto",
        "//private_join_and_compute/crypto:openssl_includes",
        "@com_github_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ec_key_util_test",
    srcs = ["ec_key_util_test.cc"],
    deps = [
        ":ec_key_util",
        ":proto_util",
        ":status_testing_includes",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_key_proto",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:openssl_includes",
        "@com_github_google_googletest//:gtest_main",
    ],
)
