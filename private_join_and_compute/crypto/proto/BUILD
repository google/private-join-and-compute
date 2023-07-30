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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "big_num_proto",
    srcs = ["big_num.proto"],
)

cc_proto_library(
    name = "big_num_cc_proto",
    deps = [":big_num_proto"],
)

proto_library(
    name = "ec_point_proto",
    srcs = ["ec_point.proto"],
)

cc_proto_library(
    name = "ec_point_cc_proto",
    deps = [":ec_point_proto"],
)

proto_library(
    name = "pedersen_proto",
    srcs = ["pedersen.proto"],
    deps = [":big_num_proto"],
)

cc_proto_library(
    name = "pedersen_cc_proto",
    deps = [":pedersen_proto"],
)

proto_library(
    name = "camenisch_shoup_proto",
    srcs = ["camenisch_shoup.proto"],
    deps = [":big_num_proto"],
)

cc_proto_library(
    name = "camenisch_shoup_cc_proto",
    deps = [":camenisch_shoup_proto"],
)

cc_library(
    name = "proto_util",
    srcs = ["proto_util.cc"],
    hdrs = ["proto_util.h"],
    deps = [
        ":big_num_cc_proto",
        ":ec_point_cc_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/util:status_includes",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "proto_util_test",
    srcs = ["proto_util_test.cc"],
    deps = [
        ":big_num_cc_proto",
        ":ec_point_cc_proto",
        ":pedersen_cc_proto",
        ":proto_util",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_util",
        "//private_join_and_compute/crypto:openssl_includes",
        "//private_join_and_compute/crypto:pedersen_over_zn",
        "//private_join_and_compute/util:status_includes",
        "//private_join_and_compute/util:status_testing_includes",
        "@com_github_google_googletest//:gtest_main",
    ],
)
