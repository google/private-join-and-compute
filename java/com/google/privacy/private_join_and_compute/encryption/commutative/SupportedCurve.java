package com.google.privacy.private_join_and_compute.encryption.commutative;

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

  /** Returns the generated parameter specs. */
  public ECGenParameterSpec getGenParameterSpec() {
    return genParameterSpec;
  }

  /** Returns the parameter specs. */
  public ECParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  public String getCurveName() {
    return curveName;
  }
}
