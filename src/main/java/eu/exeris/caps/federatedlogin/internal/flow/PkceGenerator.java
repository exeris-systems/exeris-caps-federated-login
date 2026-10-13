package eu.exeris.caps.federatedlogin.internal.flow;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * High-entropy cryptographic generator for RFC 7636 PKCE parameters, state tokens, and nonces.
 *
 * @since 0.1.0
 */
public final class PkceGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private PkceGenerator() {
    }

    /**
     * Generates a 256-bit high-entropy RFC 7636 code verifier (43 characters).
     *
     * @return URL-safe base64-encoded code verifier
     */
    public static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /**
     * Derives an RFC 7636 S256 code challenge from a code verifier:
     * {@code BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))}.
     *
     * @param codeVerifier the plain code verifier
     * @return base64url-encoded SHA-256 digest
     */
    public static String generateCodeChallenge(String codeVerifier) {
        Objects.requireNonNull(codeVerifier, "codeVerifier must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return URL_ENCODER.encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    /**
     * Generates a high-entropy anti-forgery state token (256-bit entropy).
     *
     * @return URL-safe base64-encoded state token
     */
    public static String generateState() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /**
     * Generates a high-entropy cryptographic nonce for OIDC ID token assertion (256-bit entropy).
     *
     * @return URL-safe base64-encoded nonce
     */
    public static String generateNonce() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /**
     * Computes the SHA-256 hex string index for state tokens to avoid persisting raw states directly.
     *
     * @param state raw state token
     * @return 64-character lowercase hex string
     */
    public static String computeStateHash(String state) {
        Objects.requireNonNull(state, "state must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(state.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }
}
