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

package com.google.privacy.blinders.encryption.commutative;

import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/** List of supported curves for the commutative cipher. */
public enum SupportedCurve {
  SECP256R1("secp256r1"),
  SECP384R1("secp384r1");

  // These parameter classes are conceptually immutable even though the classes are not annotated
  // accordingly.
  @SuppressWarnings("Immutable")
  private final ECParameterSpec parameterSpec;

  @SuppressWarnings("Immutable")
  private final ECGenParameterSpec genParameterSpec;

  private final String curveName;

  private SupportedCurve(String curveName) {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec(curveName));
      parameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
      genParameterSpec = new ECGenParameterSpec(curveName);
      this.curveName = curveName;
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Returns the generated parameter specs.
   *
   * @return the generated parameter specs for the curve
   */
  public ECGenParameterSpec getGenParameterSpec() {
    return genParameterSpec;
  }

  /**
   * Returns the parameter specs.
   *
   * @return the parameter specs for the curve
   */
  public ECParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  /**
   * Returns the curve name.
   *
   * @return the curve name for the curve
   */
  public String getCurveName() {
    return curveName;
  }
}
