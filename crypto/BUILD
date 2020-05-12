# Copyright 2019 Google Inc.
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

# Build file for crypto folder in open-source Private Join and Compute.

load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "openssl_includes",
    hdrs = ["openssl.inc"],
    deps = [
        "@boringssl//:ssl",
    ],
)

cc_library(
    name = "openssl_init",
    srcs = ["openssl_init.cc"],
    hdrs = ["openssl_init.h"],
    deps = [
        ":openssl_includes",
        "@boringssl//:ssl",
        "@com_github_glog_glog//:glog",
    ],
)

cc_library(
    name = "bn_util",
    srcs = [
        "big_num.cc",
        "context.cc",
    ],
    hdrs = [
        "big_num.h",
        "context.h",
    ],
    deps = [
        "//crypto:openssl_includes",
        "//crypto:openssl_init",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
    ],
)

cc_library(
    name = "mont_mul",
    srcs = [
        "mont_mul.cc",
    ],
    hdrs = [
        "mont_mul.h",
    ],
    deps = [
        ":bn_util",
        ":openssl_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "ec_util",
    srcs = [
        "ec_group.cc",
        "ec_point.cc",
    ],
    hdrs = [
        "ec_group.h",
        "ec_point.h",
    ],
    deps = [
        ":bn_util",
        "//crypto:openssl_includes",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "elgamal",
    srcs = [
        "elgamal.cc",
    ],
    hdrs = [
        "elgamal.h",
    ],
    deps = [
        ":bn_util",
        ":ec_util",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
    ],
)

cc_library(
    name = "commutative_elgamal",
    srcs = [
        "commutative_elgamal.cc",
    ],
    hdrs = [
        "commutative_elgamal.h",
    ],
    deps = [
        ":bn_util",
        ":ec_util",
        ":elgamal",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
    ],
)

cc_library(
    name = "ec_point_util",
    srcs = [
        "ec_point_util.cc",
    ],
    hdrs = [
        "ec_point_util.h",
    ],
    deps = [
        ":bn_util",
        ":ec_util",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
    ],
)

cc_library(
    name = "ec_commutative_cipher",
    srcs = [
        "ec_commutative_cipher.cc",
    ],
    hdrs = [
        "ec_commutative_cipher.h",
    ],
    deps = [
        ":bn_util",
        ":ec_util",
        ":elgamal",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
    ],
)

cc_library(
    name = "fixed_base_exp",
    srcs = [
        "fixed_base_exp.cc",
    ],
    hdrs = [
        "fixed_base_exp.h",
    ],
    deps = [
        ":bn_util",
        ":mont_mul",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "two_modulus_crt",
    srcs = [
        "two_modulus_crt.cc",
    ],
    hdrs = [
        "two_modulus_crt.h",
    ],
    deps = [
        ":bn_util",
        "@com_google_absl//absl/strings",
    ],
)

grpc_proto_library(
    name = "paillier_proto",
    srcs = ["paillier.proto"],
)

cc_library(
    name = "paillier",
    srcs = [
        "paillier.cc",
    ],
    hdrs = [
        "paillier.h",
    ],
    deps = [
        ":bn_util",
        ":fixed_base_exp",
        ":paillier_proto",
        ":two_modulus_crt",
        "//util:status",
        "//util:status_includes",
        "@com_github_gflags_gflags//:gflags",
        "@com_github_glog_glog//:glog",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:node_hash_map",
        "@com_google_absl//absl/strings",
    ],
)
