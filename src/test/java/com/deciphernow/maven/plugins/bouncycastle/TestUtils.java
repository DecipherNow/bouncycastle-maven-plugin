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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import static org.junit.Assert.assertTrue;

/**
 * Provides unit tests for the {@link Utils} class.
 */
public class TestUtils {

    private static final byte[] DATA_BYTES = TestUtils.resourceBytes("data.txt");
    private static final byte[] KEYS_BYTES = TestUtils.resourceBytes("keys.asc");
    private static final byte[] SIGNATURE_BYTES = TestUtils.resourceBytes("signature.asc");

    /**
     * Returns the bytes of a resource.
     *
     * @param name the resource
     * @return the bytes
     */
    private static byte[] resourceBytes(String name) {
        try (InputStream inputStream = TestUtils.class.getResourceAsStream(name);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            Utils.foreach(inputStream, (bytes, length) -> outputStream.write(bytes, 0, length));
            return outputStream.toByteArray();
        }
        catch (IOException exception) {
            throw new RuntimeException(String.format("Failed to process resource %s", name), exception);
        }
    }

    /**
     * Tests the {@link Utils#sign(InputStream, OutputStream, PGPSecretKey, String)} method.
     */
    @Test
    public void testSign() throws IOException, PGPException {
        try (InputStream keyStream = new ByteArrayInputStream(KEYS_BYTES);
             InputStream dataStream = new ByteArrayInputStream(DATA_BYTES);
             ByteArrayOutputStream signatureStream = new ByteArrayOutputStream()) {

            PGPSecretKeyRingCollection keys = Utils.loadSecretKeyRings(keyStream);
            PGPSecretKey privateKey = Utils.find("immortal@deciphernow.com", keys);
            PGPPublicKey publicKey = privateKey.getPublicKey();
            Utils.sign(dataStream, signatureStream, privateKey, "latrommI");
            ByteArrayInputStream signatureInputStream = new ByteArrayInputStream(signatureStream.toByteArray());
            dataStream.reset();
            assertTrue(Utils.verify(dataStream, signatureInputStream, publicKey));
        }
    }

    /**
     * Tests the {@link Utils#verify(InputStream, InputStream, PGPPublicKey)} method.
     */
    @Test
    public void testVerify() throws IOException, PGPException {
        try (InputStream keyInputStream = this.getClass().getResourceAsStream("keys.asc");
             InputStream sampleInputStream = this.getClass().getResourceAsStream("data.txt");
             InputStream signatureInputStream = this.getClass().getResourceAsStream("signature.asc")) {

            PGPSecretKeyRingCollection keys = Utils.loadSecretKeyRings(keyInputStream);
            PGPSecretKey privateKey = Utils.find("immortal@deciphernow.com", keys);
            PGPPublicKey publicKey = privateKey.getPublicKey();
            assertTrue(Utils.verify(sampleInputStream, signatureInputStream, publicKey));
        }
    }
}
