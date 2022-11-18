package com.google.privacy.private_join_and_compute.encryption.commutative;

import com.google.common.base.Preconditions;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of EcCommutativeCipher using BouncyCastle.
 *
 * <p>EcCommutativeCipher class with the property that K1(K2(a)) = K2(K1(a)) where K(a) is
 * encryption with the key K.
 *
 * <p>This class allows two parties to determine if they share the same value, without revealing the
 * sensitive value to each other. See the paper "Using Commutative Encryption to Share a Secret" at
 * https://eprint.iacr.org/2008/356.pdf for reference.
 *
 * <p>The encryption is performed over an elliptic curve.
 *
 * <p>Security: The provided bit security is half the number of bits of the underlying curve. For
 * example, using curve secp160r1 gives 80 bit security.
 */
public final class EcCommutativeCipher extends EcCommutativeCipherBase {

  @SuppressWarnings("Immutable")
  private final ECNamedDomainParameters domainParams;

  private static ECNamedDomainParameters getDomainParams(SupportedCurve curve) {
    String curveName = curve.getCurveName();
    X9ECParameters ecParams = SECNamedCurves.getByName(curveName);
    return new ECNamedDomainParameters(
        SECNamedCurves.getOID(curveName),
        ecParams.getCurve(),
        ecParams.getG(),
        ecParams.getN(),
        ecParams.getH(),
        ecParams.getSeed());
  }

  private EcCommutativeCipher(HashType hashType, ECPrivateKey key, SupportedCurve ecCurve) {
    super(hashType, key, ecCurve);
    domainParams = getDomainParams(ecCurve);
  }

  /**
   * Creates an EcCommutativeCipher object with a new random private key based on the {@code curve}.
   * Use this method when the key is created for the first time or it needs to be refreshed.
   *
   * <p>New users should use SHA256 as the underlying hash function.
   */
  public static EcCommutativeCipher createWithNewKey(SupportedCurve curve, HashType hashType) {
    return new EcCommutativeCipher(hashType, createPrivateKey(curve), curve);
  }

  /**
   * Creates an EcCommutativeCipher object with a new random private key based on the {@code curve}.
   * Use this method when the key is created for the first time or it needs to be refreshed.
   *
   * <p>The underlying hash type will be SHA256.
   */
  public static EcCommutativeCipher createWithNewKey(SupportedCurve curve) {
    return createWithNewKey(curve, HashType.SHA256);
  }

  /**
   * Creates an EcCommutativeCipher object from the given key. A new key should be created for each
   * session and all values should be unique in one session because the encryption is deterministic.
   * Use this when the key is stored securely to be used at different steps of the protocol in the
   * same session or by multiple processes.
   *
   * <p>New users should use SHA256 as the underying hash function.
   *
   * @throws IllegalArgumentException if the key encoding is invalid.
   */
  public static EcCommutativeCipher createFromKey(
      SupportedCurve curve, HashType hashType, byte[] keyBytes) {
    try {
      BigInteger key = byteArrayToBigIntegerCppCompatible(keyBytes);
      return new EcCommutativeCipher(hashType, decodePrivateKey(key, curve), curve);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  /**
   * Creates an EcCommutativeCipher object from the given key. A new key should be created for each
   * session and all values should be unique in one session because the encryption is deterministic.
   * Use this when the key is stored securely to be used at different steps of the protocol in the
   * same session or by multiple processes.
   *
   * <p>The underlying hash type will be SHA256.
   *
   * @throws IllegalArgumentException if the key encoding is invalid.
   */
  public static EcCommutativeCipher createFromKey(SupportedCurve curve, byte[] keyBytes) {
    return createFromKey(curve, HashType.SHA256, keyBytes);
  }

  // copybara:strip_begin(Remove deprecated functions)
  /**
   * Creates an EcCommutativeCipher object from the given key. A new key should be created for each
   * session and all values should be unique in one session because the encryption is deterministic.
   * Use this when the key is stored securely to be used at different steps of the protocol in the
   * same session or by multiple processes.
   *
   * @deprecated This function is incompatible with the C++ implementation.
   * @throws IllegalArgumentException if the key encoding is invalid.
   */
  @Deprecated
  public static EcCommutativeCipher createFromKeyCppIncompatible(
      SupportedCurve curve, byte[] keyBytes) {
    try {
      BigInteger key = new BigInteger(keyBytes);
      return new EcCommutativeCipher(HashType.SHA256, decodePrivateKey(key, curve), curve);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }
  // copybara:strip_end

  /**
   * Checks if a ciphertext (compressed encoded point) is on the elliptic curve.
   *
   * @param ciphertext the ciphertext that needs verification if it's on the curve.
   * @return true if the point is valid and non-infinite
   */
  public static boolean validateCiphertext(byte[] ciphertext, SupportedCurve supportedCurve) {
    try {
      ECPoint point = getDomainParams(supportedCurve).getCurve().decodePoint(ciphertext);
      return point.isValid() && !point.isInfinity();
    } catch (IllegalArgumentException ignored) {
      return false;
    }
  }

  /**
   * Internal implementation of {@code #hashIntoTheCurve} method.
   *
   * <p>See the documentation of {@code #hashIntoTheCurve} for details.
   */
  @Override
  protected java.security.spec.ECPoint hashIntoTheCurveInternal(byte[] byteId) {
    ECCurve ecCurve = domainParams.getCurve();
    ECFieldElement a = ecCurve.getA();
    ECFieldElement b = ecCurve.getB();
    BigInteger p = ((Fp) ecCurve).getQ();
    BigInteger x = randomOracle(byteId, p, hashType);
    while (true) {
      ECFieldElement fieldX = ecCurve.fromBigInteger(x);
      // y2 = x ^ 3 + a x + b
      ECFieldElement y2 = fieldX.multiply(fieldX.square().add(a)).add(b);
      ECFieldElement y2Sqrt = y2.sqrt();
      if (y2Sqrt != null) {
        if (y2Sqrt.toBigInteger().testBit(0)) {
          return new java.security.spec.ECPoint(
              fieldX.toBigInteger(), y2Sqrt.negate().toBigInteger());
        }
        return new java.security.spec.ECPoint(fieldX.toBigInteger(), y2Sqrt.toBigInteger());
      }
      x = randomOracle(bigIntegerToByteArrayCppCompatible(x), p, hashType);
    }
  }

  /**
   * Hashes bytes to a point on the elliptic curve y^2 = x^3 + ax + b over a prime field.
   *
   * <p>To hash byteId to a point on the curve, the algorithm first computes an integer hash value x
   * = h(byteId) and determines whether x is the abscissa of a point on the elliptic curve y^2 = x^3
   * + ax + b. If so, we take the positive square root of y^2. If not, set x = h(x) and try again.
   *
   * @param byteId the value to hash into the curve
   * @return a point on the curve encoded in compressed form as defined in ANSI X9.62 ECDSA
   */
  @Override
  public byte[] hashIntoTheCurve(byte[] byteId) {
    return convertECPoint(hashIntoTheCurveInternal(byteId)).getEncoded(true);
  }

  /**
   * Encrypts an ECPoint with the private key.
   *
   * @param point a point to encrypt
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  private byte[] encrypt(ECPoint point) {
    return point.multiply(privateKey.getS()).getEncoded(true);
  }

  /**
   * Encrypts an input with the private key, first hashing the input to the curve.
   *
   * @param plaintext bytes to encrypt
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  @Override
  public byte[] encrypt(byte[] plaintext) {
    java.security.spec.ECPoint point = hashIntoTheCurveInternal(plaintext);
    return encrypt(convertECPoint(point));
  }

  /**
   * Re-encrypts an encoded point with the private key.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   * @throws IllegalArgumentException if the encoding is invalid or if the decoded point is not on
   *     the curve, or is the point at infinity
   */
  @Override
  public byte[] reEncrypt(byte[] ciphertext) {
    ECPoint point = checkPointOnCurve(ciphertext);
    return encrypt(point);
  }

  /**
   * Decrypts an encoded point that has been previously encrypted with the private key. Does not
   * reverse hashing to the curve.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   * @throws IllegalArgumentException if the encoding is invalid or if the decoded point is not on
   *     the curve, or is the point at infinity
   */
  @Override
  public byte[] decrypt(byte[] ciphertext) {
    ECPoint point = checkPointOnCurve(ciphertext);
    BigInteger privateKeyInverse = privateKey.getS().modInverse(privateKey.getParams().getOrder());
    return point.multiply(privateKeyInverse).getEncoded(true);
  }

  /**
   * Checks that a compressed encoded point is on the elliptic curve.
   *
   * @param compressedPoint the point that needs verification
   * @return a valid ECPoint obtained from the compressed point
   * @throws IllegalArgumentException if the encoding is invalid, the point is not on the curve, or
   *     is the point at infinity
   */
  private ECPoint checkPointOnCurve(byte[] compressedPoint) {
    ECPoint point = domainParams.getCurve().decodePoint(compressedPoint);
    Preconditions.checkArgument(point.isValid(), "Invalid point: the point is not on the curve");
    Preconditions.checkArgument(!point.isInfinity(), "Invalid point: the point is at infinity");
    return point;
  }

  /**
   * Encodes an ECPoint.
   *
   * @param point a point to encrypt
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  @Override
  protected byte[] getEncoded(java.security.spec.ECPoint point) {
    return convertECPoint(point).getEncoded(true);
  }

  /**
   * Checks validity of a point.
   *
   * @param point a point to check
   * @return true iff point is valid.
   */
  @Override
  protected boolean isValid(java.security.spec.ECPoint point) {
    return convertECPoint(point).isValid();
  }

  /**
   * Checks whether a point is at infinity.
   *
   * @param point a point to check
   * @return true iff point is infinity.
   */
  @Override
  protected boolean isInfinity(java.security.spec.ECPoint point) {
    return convertECPoint(point).isInfinity();
  }

  /** Converts a JCE ECPoint object to a BouncyCastle ECPoint. */
  private ECPoint convertECPoint(java.security.spec.ECPoint point) {
    return domainParams.getCurve().createPoint(point.getAffineX(), point.getAffineY());
  }
}
