package eu.exeris.caps.federatedlogin.internal.crypto;

import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginException;
import eu.exeris.caps.federatedlogin.api.exception.FlowStateUnreadableException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * AES-256-GCM sealing of ephemeral PKCE verifiers and other flow data at rest.
 *
 * <p>Every payload is {@code <keyId>:<base64url(iv || ciphertext || tag)>}. The additional
 * authenticated data binds the payload to the flow it belongs to, so a sealed value copied onto another
 * state row does not open. The key comes from a {@link FlowStateKeyring}, shared by every node.
 *
 * @since 0.1.0
 */
public final class FlowStateCrypto {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final FlowStateKeyring keyring;

    public FlowStateCrypto(FlowStateKeyring keyring) {
        this.keyring = Objects.requireNonNull(keyring, "keyring must not be null");
    }

    /**
     * Seals {@code plaintext} under the active key, bound to {@code associatedData}.
     *
     * @param plaintext      value to seal; {@code null} yields {@code null}
     * @param associatedData identifier of the flow the value belongs to
     * @return the sealed payload
     * @throws FederatedLoginException if sealing fails
     */
    public String encrypt(String plaintext, String associatedData) {
        if (plaintext == null) {
            return null;
        }
        Objects.requireNonNull(associatedData, "associatedData must not be null");
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keyring.activeKey(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherBytes.length);
            buffer.put(iv);
            buffer.put(cipherBytes);
            return keyring.activeId() + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(buffer.array());
        } catch (GeneralSecurityException e) {
            throw new FederatedLoginException("Failed to seal flow state", e);
        }
    }

    /**
     * Opens a payload sealed by {@link #encrypt(String, String)}.
     *
     * @param sealed         the sealed payload; {@code null} yields {@code null}
     * @param associatedData identifier of the flow the value belongs to
     * @return the plaintext
     * @throws FlowStateUnreadableException if the payload is malformed, names an unknown key, or does
     *                                      not authenticate for this {@code associatedData}
     */
    public String decrypt(String sealed, String associatedData) {
        if (sealed == null) {
            return null;
        }
        Objects.requireNonNull(associatedData, "associatedData must not be null");
        int colon = sealed.indexOf(':');
        if (colon <= 0) {
            throw new FlowStateUnreadableException("Stored flow state is not in the sealed format");
        }
        String keyId = sealed.substring(0, colon);
        SecretKey key = keyring.key(keyId).orElseThrow(() ->
                new FlowStateUnreadableException("Stored flow state is sealed under unknown key '" + keyId + "'"));
        try {
            byte[] combined = Base64.getUrlDecoder().decode(sealed.substring(colon + 1));
            if (combined.length <= GCM_IV_LENGTH) {
                throw new FlowStateUnreadableException("Stored flow state payload is too short");
            }
            ByteBuffer buffer = ByteBuffer.wrap(combined);
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);
            byte[] cipherBytes = new byte[buffer.remaining()];
            buffer.get(cipherBytes);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(cipherBytes), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new FlowStateUnreadableException("Stored flow state does not authenticate under key '" + keyId + "'", e);
        }
    }
}
