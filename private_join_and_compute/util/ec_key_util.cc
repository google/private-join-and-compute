/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "private_join_and_compute/util/ec_key_util.h"

#include "absl/strings/str_cat.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/recordio.h"

namespace private_join_and_compute::ec_key_util {

Status GenerateEcKey(int curve_id, absl::string_view ec_key_filename) {
  Context context;
  ASSIGN_OR_RETURN(ECGroup ec_group, ECGroup::Create(curve_id, &context));
  BigNum key = ec_group.GeneratePrivateKey();
  EcKeyProto key_proto;
  key_proto.set_curve_id(curve_id);
  key_proto.set_key(key.ToBytes());
  return ProtoUtils::WriteProtoToFile(key_proto, ec_key_filename);
}

StatusOr<BigNum> DeserializeEcKey(Context* context, int curve_id,
                                  EcKeyProto ec_key_proto) {
  if (curve_id != ec_key_proto.curve_id()) {
    return InvalidArgumentError(absl::StrCat(
        "EC key conversion failed, the given curve_id ", curve_id,
        " doesn't match the proto curve id ", ec_key_proto.curve_id()));
  }
  return context->CreateBigNum(ec_key_proto.key());
}

}  // namespace private_join_and_compute::ec_key_util
