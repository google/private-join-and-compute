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

load("@rules_python//python:packaging.bzl", "py_package", "py_wheel")

package(default_visibility = ["//visibility:public"])

# Creates private_join_and_compute-0.0.1.whl
py_wheel(
    name = "private_join_and_compute_wheel",
    classifiers = [
        "License :: OSI Approved :: Apache Software License",
    ],
    description_file = "README",
    # This should match the project name on PyPI. It's also the name that is used to refer to the
    # package in other packages' dependencies.
    distribution = "private_join_and_compute",
    python_tag = "py3",
    requires = [
        "absl-py",
        "six",
    ],
    version = "0.0.1",
    deps = [
        "//private_join_and_compute/py/ciphers:ec_cipher",
        "//private_join_and_compute/py/crypto_util:converters",
        "//private_join_and_compute/py/crypto_util:elliptic_curve",
        "//private_join_and_compute/py/crypto_util:ssl_util",
        "//private_join_and_compute/py/crypto_util:supported_curves",
        "//private_join_and_compute/py/crypto_util:supported_hashes",
    ],
)
