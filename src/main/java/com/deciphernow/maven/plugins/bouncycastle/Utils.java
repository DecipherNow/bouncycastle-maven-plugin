/*
 * Copyright 2017 Decipher Technology Studios LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.deciphernow.maven.plugins.bouncycastle;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Iterator;
import java.util.function.BiConsumer;

/**
 * Provides utility methods for working with Bouncy Castle.
 */
final class Utils {

  /**
   * The buffer size used for IO operations.
   */
  private static final int BUFFER_SIZE = 4096;

  /**
   * Initializes a new instance of the {@link Utils} class.
   */
  private Utils() {
  }

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Finds the secret key for a user id in a {@link PGPSecretKeyRingCollection}.
   *
   * @param userId user id
   * @param collection the collection
   * @return the secret key or null if not found
   */
  static PGPSecretKey find(String userId, PGPSecretKeyRingCollection collection) {
    for (PGPSecretKeyRing ring : collection) {
      if (ring != null) {
        return find(userId, ring);
      }
    }
    return null;
  }

  /**
   * Finds the secret key for a user oin a {@link PGPSecretKeyRing}.
   *
   * @param userId the user id
   * @param ring the ring
   * @return the secret key or null if not found
   */
  static PGPSecretKey find(String userId, PGPSecretKeyRing ring) {
    for (PGPSecretKey key : ring) {
      if (hasUserId(userId, key)) {
        return key;
      }
    }
    return null;
  }

  /**
   * Returns a value indicating whether a user id is specified for a secret key.
   *
   * @param userId the user id
   * @param key the key
   * @return {@code true} if the user id exists; otherwise, {@code false}
   */
  static boolean hasUserId(String userId, PGPSecretKey key) {
    Iterator iterator = key.getUserIDs();
    while (iterator.hasNext()) {
      if (((String) iterator.next()).contains(userId)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Loads a {@link PGPSecretKeyRingCollection} from a stream.
   *
   * @param stream the stream
   * @return the key rings
   * @throws IOException if an exception is thrown reading the stream
   * @throws PGPException if an exception is thrown creating the key rings
   */
  static PGPSecretKeyRingCollection loadSecretKeyRings(InputStream stream) throws IOException, PGPException {
    InputStream decoderStream = PGPUtil.getDecoderStream(stream);
    KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();
    return new PGPSecretKeyRingCollection(decoderStream, fingerPrintCalculator);
  }


  /**
   * Writes a detached signature for the provided data stream to the provided signature stream using the provided key
   * and passphrase.
   *
   * @param dataStream the data stream
   * @param signatureStream the signature stream
   * @param key the key
   * @param passphrase the passphrase
   * @throws IOException if an exception is thrown reading or writing to or from the streams
   * @throws PGPException if an exception is thrown working with the keys
   */
  static void sign(InputStream dataStream, OutputStream signatureStream, PGPSecretKey key, String passphrase)
          throws IOException, PGPException {

    PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
            .setProvider("BC")
            .build(passphrase.toCharArray());
    PGPContentSignerBuilder builder = new JcaPGPContentSignerBuilder(key.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
            .setProvider("BC");
    PGPSignatureGenerator generator = new PGPSignatureGenerator(builder);
    generator.init(PGPSignature.BINARY_DOCUMENT, key.extractPrivateKey(decryptor));

    try (OutputStream armoredOutputStream = new ArmoredOutputStream(signatureStream);
         OutputStream bcpgOutputStream = new BCPGOutputStream(armoredOutputStream)) {

      foreach(dataStream, (byte[] buffer, Integer length) -> generator.update(buffer, 0, length));

      generator.generate().encode(bcpgOutputStream);
    }
  }

  /**
   * Verifies that a signature input stream was generated for another input stream using a key.
   *
   * @param dataStream the stream containing the signed data
   * @param signatureStream the stream containing the signature
   * @param key the key
   * @return {@code true} if the signature was verified; otherwise, {@code false}
   * @throws IOException if an exception is thrown while reading from the streams
   * @throws PGPException if an exception is thrown working with the keys
   */
  public static boolean verify(InputStream dataStream, InputStream signatureStream, PGPPublicKey key)
          throws IOException, PGPException {

    try (InputStream decoderInputStream = PGPUtil.getDecoderStream(signatureStream)) {

      PGPObjectFactory objectFactory = new PGPObjectFactory(decoderInputStream, new JcaKeyFingerprintCalculator());
      PGPSignatureList signatures = (PGPSignatureList) objectFactory.nextObject();

      PGPSignature signature = signatures.get(0);
      signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

      foreach(dataStream, (byte[] buffer, Integer length) -> signature.update(buffer, 0, length));

      return signature.verify();
    }
  }

  /**
   * Provides a convenience function for reading bytes from a stream and yielding them to a consumer.
   *
   * @param stream the stream
   * @param consumer the consumer
   */
  static void foreach(InputStream stream, BiConsumer<byte[], Integer> consumer) throws IOException {
    int length;
    byte[] buffer = new byte[BUFFER_SIZE];
    while ((length = stream.read(buffer, 0, buffer.length)) > 0) {
      consumer.accept(buffer, length);
    }
  }
}
