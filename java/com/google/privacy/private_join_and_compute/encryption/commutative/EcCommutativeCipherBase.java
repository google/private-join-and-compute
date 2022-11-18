package com.google.privacy.private_join_and_compute.encryption.commutative;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * EcCommutativeCipher class with the property that K1(K2(a)) = K2(K1(a)) where K(a) is encryption
 * with the key K.
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
public abstract class EcCommutativeCipherBase {
  /** List of supported underlying hash types for the commutative cipher. */
  public enum HashType {
    SHA256(256),
    SHA384(384),
    SHA512(512);

    private final int hashBitLength;

    private HashType(int hashBitLength) {
      this.hashBitLength = hashBitLength;
    }

    /** Returns the bit length. */
    public int getHashBitLength() {
      return hashBitLength;
    }
  }

  // EC classes are conceptually immutable even though the class is not annotated accordingly.
  @SuppressWarnings("Immutable")
  protected final ECPrivateKey privateKey;

  @SuppressWarnings("Immutable")
  protected final SupportedCurve ecCurve;

  protected final HashType hashType;

  /** Creates an EcCommutativeCipherBase object with the given private key and curve. */
  protected EcCommutativeCipherBase(HashType hashType, ECPrivateKey key, SupportedCurve ecCurve) {
    this.privateKey = key;
    this.ecCurve = ecCurve;
    this.hashType = hashType;
  }

  /** Decodes the private key from BigInteger. */
  protected static ECPrivateKey decodePrivateKey(BigInteger key, SupportedCurve curve)
      throws InvalidKeySpecException {
    checkPrivateKey(key, curve.getParameterSpec());
    ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(key, curve.getParameterSpec());
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      return (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  /** Creates a new random private key. */
  protected static ECPrivateKey createPrivateKey(SupportedCurve curve) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(curve.getParameterSpec(), new SecureRandom());
      return (ECPrivateKey) generator.generateKeyPair().getPrivate();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Encrypts an input with the private key, first hashing the input to the curve.
   *
   * @param plaintext bytes to encrypt
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  public abstract byte[] encrypt(byte[] plaintext);

  /**
   * Re-encrypts an encoded point with the private key.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   */
  public abstract byte[] reEncrypt(byte[] ciphertext);

  /**
   * Decrypts an encoded point that has been previously encrypted with the private key. Does not
   * reverse hashing to the curve.
   *
   * @param ciphertext an encoded point as defined in ANSI X9.62 ECDSA
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA
   */
  public abstract byte[] decrypt(byte[] ciphertext);

  /**
   * Hashes bytes to a point on the elliptic curve y^2 = x^3 + ax + b over a prime field.
   */
  @VisibleForTesting
  abstract ECPoint hashIntoTheCurveInternal(byte[] byteId);

  /**
   * Hashes bytes to a point on the elliptic curve y^2 = x^3 + ax + b over a prime field. All
   * implementations must match the C++ version:
   *
   * <p>The resulting point is returned encoded in compressed form as defined in ANSI X9.62 ECDSA.
   */
  public abstract byte[] hashIntoTheCurve(byte[] byteId);

  /**
   * A random oracle function mapping x deterministically into a large domain.
   *
   * <p>// copybara:strip_begin(Remove internal comment)
   *
   * <p>The random oracle is similar to the example given in the last paragraph of Chapter 6 of [1]
   * where the output is expanded by successively hashing the concatenation of the input with a
   * fixed sized counter starting from 1.
   *
   * <p>[1] Bellare, Mihir, and Phillip Rogaway. "Random oracles are practical: A paradigm for
   * designing efficient protocols." Proceedings of the 1st ACM conference on Computer and
   * communications security. ACM, 1993.
   *
   * <p>Returns a value from the set [0, max_value).
   *
   * <p>Check Error: if bit length of max_value is greater than 130048. Since the counter used for
   * expanding the output is expanded to 8 bit length (hard-coded), any counter value that is
   * greater than 512 would cause variable length inputs passed to the underlying
   * sha256/sha384/sha512 calls and might make this random oracle's output not uniform across the
   * output domain.
   *
   * <p>The output length is increased by a security value of 256 which reduces the bias of
   * selecting certain values more often than others when max_value is not a multiple of 2.
   */
  public static BigInteger randomOracle(byte[] bytes, BigInteger maxValue, HashType hashType) {
    int hashBitLength = hashType.getHashBitLength();
    int outputBitLength = maxValue.bitLength() + hashBitLength;
    int iterCount = (outputBitLength + hashBitLength - 1) / hashBitLength;
    int excessBitCount = (iterCount * hashBitLength) - outputBitLength;
    BigInteger hashOutput = BigInteger.ZERO;
    BigInteger counter = BigInteger.ONE;
    for (int i = 1; i < iterCount + 1; ++i) {
      hashOutput = hashOutput.shiftLeft(hashBitLength);
      byte[] counterBytes = bigIntegerToByteArrayCppCompatible(counter);
      byte[] hashInput = Bytes.concat(counterBytes, bytes);
      byte[] hashCode;
      switch (hashType) {
        case SHA256:
          hashCode = Hashing.sha256().hashBytes(hashInput).asBytes();
          break;
        case SHA384:
          hashCode = Hashing.sha384().hashBytes(hashInput).asBytes();
          break;
        default:
          hashCode = Hashing.sha512().hashBytes(hashInput).asBytes();
      }
      hashOutput = hashOutput.add(byteArrayToBigIntegerCppCompatible(hashCode));
      counter = counter.add(BigInteger.ONE);
    }
    return hashOutput.shiftRight(excessBitCount).mod(maxValue);
  }

  /** Checks the private key is between 1 and the order of the group. */
  private static void checkPrivateKey(BigInteger key, ECParameterSpec params) {
    if (key.compareTo(BigInteger.ONE) <= 0 || key.compareTo(params.getOrder()) >= 0) {
      throw new IllegalArgumentException("The given key is out of bounds.");
    }
  }

  /**
   * Returns the private key bytes.
   *
   * @return the private key bytes for this EcCommutativeCipher.
   */
  public byte[] getPrivateKeyBytes() {
    return bigIntegerToByteArrayCppCompatible(privateKey.getS());
  }

  // copybara:strip_begin(Remove deprecated functions)
  /**
   * Returns the private key bytes.
   *
   * @deprecated This function is incompatible with the C++ implementation.
   * @return the private key bytes for this EcCommutativeCipher.
   */
  @Deprecated
  public byte[] getPrivateKeyBytesCppIncompatible() {
    return privateKey.getS().toByteArray();
  }
  // copybara:strip_end

  /**
   * This function converts a BigInteger into a byte array in big-endian form without two's
   * complement representation. This function is compatible with C++ OpenSSL's BigNum
   * implementation.
   */
  public static byte[] bigIntegerToByteArrayCppCompatible(BigInteger value) {
    byte[] signedArray = value.toByteArray();
    int leadingZeroes = 0;
    while (signedArray[leadingZeroes] == 0) {
      leadingZeroes++;
    }
    byte[] unsignedArray = new byte[signedArray.length - leadingZeroes];
    System.arraycopy(signedArray, leadingZeroes, unsignedArray, 0, unsignedArray.length);
    return unsignedArray;
  }

  /**
   * This function converts bytes to BigInteger. The input bytes are assumed to be in big-endian
   * form. The function converts the bytes into two's complement big-endian form before converting
   * into a BigInteger. This function matches the C++ OpenSSL implementation of bytes to BigNum.
   */
  public static BigInteger byteArrayToBigIntegerCppCompatible(byte[] bytes) {
    byte[] twosComplement = new byte[bytes.length + 1];
    twosComplement[0] = 0;
    System.arraycopy(bytes, 0, twosComplement, 1, bytes.length);
    return new BigInteger(twosComplement);
  }

  /**
   * Encodes a point.
   *
   * @param point a point to encode
   * @return an encoded point in compressed form as defined in ANSI X9.62 ECDSA.
   */
  @VisibleForTesting
  abstract byte[] getEncoded(ECPoint point);

  /**
   * Checks validity of a point.
   *
   * @param point a point to check
   * @return true iff point is valid.
   */
  @VisibleForTesting
  abstract boolean isValid(ECPoint point);

  /**
   * Checks whether a point is at infinity.
   *
   * @param point a point to check
   * @return true iff point is infinity.
   */
  @VisibleForTesting
  abstract boolean isInfinity(ECPoint point);
}

