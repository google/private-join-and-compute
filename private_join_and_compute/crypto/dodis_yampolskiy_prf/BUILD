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

# Implementation of Dodis-Yampolskiy VRF and OPRF.

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "dy_verifiable_random_function_proto",
    srcs = ["dy_verifiable_random_function.proto"],
    deps = [
        "//private_join_and_compute/crypto/proto:big_num_proto",
        "//private_join_and_compute/crypto/proto:ec_point_proto",
        "//private_join_and_compute/crypto/proto:pedersen_proto",
    ],
)

cc_proto_library(
    name = "dy_verifiable_random_function_cc_proto",
    deps = [":dy_verifiable_random_function_proto"],
)

cc_library(
    name = "dy_verifiable_random_function",
    srcs = [
        "dy_verifiable_random_function.cc",
    ],
    hdrs = [
        "dy_verifiable_random_function.h",
    ],
    deps = [
        ":dy_verifiable_random_function_cc_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:pedersen_over_zn",
        "//private_join_and_compute/crypto/proto:proto_util",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "dy_verifiable_random_function_test",
    srcs = [
        "dy_verifiable_random_function_test.cc",
    ],
    deps = [
        ":dy_verifiable_random_function",
        ":dy_verifiable_random_function_cc_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:pedersen_over_zn",
        "//private_join_and_compute/crypto/proto:big_num_cc_proto",
        "//private_join_and_compute/crypto/proto:pedersen_cc_proto",
        "//private_join_and_compute/crypto/proto:proto_util",
        "//private_join_and_compute/util:status_testing_includes",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
    ],
)

proto_library(
    name = "bb_oblivious_signature_proto",
    srcs = ["bb_oblivious_signature.proto"],
    deps = [
        "//private_join_and_compute/crypto/proto:big_num_proto",
        "//private_join_and_compute/crypto/proto:camenisch_shoup_proto",
        "//private_join_and_compute/crypto/proto:ec_point_proto",
        "//private_join_and_compute/crypto/proto:pedersen_proto",
    ],
)

cc_proto_library(
    name = "bb_oblivious_signature_cc_proto",
    deps = [":bb_oblivious_signature_proto"],
)

cc_library(
    name = "bb_oblivious_signature",
    srcs = [
        "bb_oblivious_signature.cc",
    ],
    hdrs = [
        "bb_oblivious_signature.h",
    ],
    deps = [
        ":bb_oblivious_signature_cc_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:camenisch_shoup",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:pedersen_over_zn",
        "//private_join_and_compute/crypto/proto:big_num_cc_proto",
        "//private_join_and_compute/crypto/proto:camenisch_shoup_cc_proto",
        "//private_join_and_compute/crypto/proto:ec_point_cc_proto",
        "//private_join_and_compute/crypto/proto:proto_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "bb_oblivious_signature_test",
    timeout = "long",
    srcs = [
        "bb_oblivious_signature_test.cc",
    ],
    deps = [
        ":bb_oblivious_signature",
        ":bb_oblivious_signature_cc_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:camenisch_shoup",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:pedersen_over_zn",
        "//private_join_and_compute/crypto/proto:big_num_cc_proto",
        "//private_join_and_compute/crypto/proto:camenisch_shoup_cc_proto",
        "//private_join_and_compute/crypto/proto:ec_point_cc_proto",
        "//private_join_and_compute/crypto/proto:pedersen_cc_proto",
        "//private_join_and_compute/crypto/proto:proto_util",
        "//private_join_and_compute/util:status_testing_includes",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
    ],
)
