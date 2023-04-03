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

load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

grpc_proto_library(
    name = "match_proto",
    srcs = ["match.proto"],
)

grpc_proto_library(
    name = "private_intersection_sum_proto",
    srcs = ["private_intersection_sum.proto"],
    deps = [
        ":match_proto",
    ],
)

grpc_proto_library(
    name = "private_join_and_compute_proto",
    srcs = ["private_join_and_compute.proto"],
    deps = [
        ":private_intersection_sum_proto",
    ],
)

cc_library(
    name = "message_sink",
    hdrs = ["message_sink.h"],
    deps = [
        ":private_join_and_compute_proto",
        "//private_join_and_compute/util:status_includes",
        "@com_google_absl//absl/memory",
    ],
)

cc_library(
    name = "protocol_client",
    hdrs = ["protocol_client.h"],
    deps = [
        ":message_sink",
        ":private_join_and_compute_proto",
        "//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "client_impl",
    srcs = ["client_impl.cc"],
    hdrs = ["client_impl.h"],
    deps = [
        ":match_proto",
        ":message_sink",
        ":private_intersection_sum_proto",
        ":private_join_and_compute_proto",
        ":protocol_client",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_commutative_cipher",
        "//private_join_and_compute/crypto:paillier",
        "//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "protocol_server",
    hdrs = ["protocol_server.h"],
    deps = [
        ":message_sink",
        ":private_join_and_compute_proto",
        "//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "server_impl",
    srcs = ["server_impl.cc"],
    hdrs = ["server_impl.h"],
    deps = [
        ":match_proto",
        ":message_sink",
        ":private_intersection_sum_proto",
        ":private_join_and_compute_proto",
        ":protocol_server",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/crypto:ec_commutative_cipher",
        "//private_join_and_compute/crypto:paillier",
        "//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "data_util",
    srcs = ["data_util.cc"],
    hdrs = ["data_util.h"],
    deps = [
        ":match_proto",
        "//private_join_and_compute/crypto:bn_util",
        "//private_join_and_compute/util:status_includes",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "generate_dummy_data",
    srcs = ["generate_dummy_data.cc"],
    deps = [
        ":data_util",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
    ],
)

cc_library(
    name = "private_join_and_compute_rpc_impl",
    srcs = ["private_join_and_compute_rpc_impl.cc"],
    hdrs = ["private_join_and_compute_rpc_impl.h"],
    deps = [
        ":message_sink",
        ":private_join_and_compute_proto",
        ":protocol_server",
        "//private_join_and_compute/util:status_includes",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "server",
    srcs = ["server.cc"],
    deps = [
        ":data_util",
        ":private_join_and_compute_proto",
        ":private_join_and_compute_rpc_impl",
        ":protocol_server",
        ":server_impl",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    deps = [
        ":client_impl",
        ":data_util",
        ":private_join_and_compute_proto",
        ":protocol_client",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
    ],
)
