package eu.exeris.caps.federatedlogin.internal.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * AES-256-GCM encryption helper for encrypting ephemeral PKCE verifiers and sensitive flow data at rest.
 *
 * @since 0.1.0
 */
public final class FlowStateCrypto {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96-bit IV
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey key;

    public FlowStateCrypto() {
        this(generateDefaultKey());
    }

    public FlowStateCrypto(SecretKey key) {
        this.key = Objects.requireNonNull(key, "key must not be null");
    }

    public FlowStateCrypto(byte[] keyBytes) {
        Objects.requireNonNull(keyBytes, "keyBytes must not be null");
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("Key bytes must be exactly 32 bytes (256 bits)");
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    private static SecretKey generateDefaultKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES key generation unavailable", e);
        }
    }

    /**
     * Encrypts plaintext string using AES-256-GCM.
     *
     * @param plaintext string to encrypt
     * @return base64-encoded payload containing IV + ciphertext with authentication tag
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherBytes.length);
            buffer.put(iv);
            buffer.put(cipherBytes);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer.array());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt flow state", e);
        }
    }

    /**
     * Decrypts ciphertext previously encrypted by {@link #encrypt(String)}.
     *
     * @param encryptedBase64 base64-encoded encrypted payload
     * @return decrypted plaintext string
     */
    public String decrypt(String encryptedBase64) {
        if (encryptedBase64 == null) {
            return null;
        }
        try {
            byte[] combined = Base64.getUrlDecoder().decode(encryptedBase64);
            if (combined.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted payload length");
            }

            ByteBuffer buffer = ByteBuffer.wrap(combined);
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);

            byte[] cipherBytes = new byte[buffer.remaining()];
            buffer.get(cipherBytes);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt flow state", e);
        }
    }
}
