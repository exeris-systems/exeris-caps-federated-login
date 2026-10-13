package eu.exeris.caps.federatedlogin.internal.repository;

import java.time.Instant;
import java.util.Objects;

/**
 * Record holding ephemeral state for an active authorization flow.
 *
 * @param stateHash          SHA-256 hash of the flow's state token (lookup index)
 * @param providerId         identifier of the provider initiated
 * @param redirectUri        registered redirect URI used
 * @param targetPostLoginUrl requested destination URL after login completes
 * @param codeVerifier       RFC 7636 PKCE code verifier (encrypted when stored in database)
 * @param nonce              cryptographic OIDC nonce
 * @param createdAt          timestamp when flow was initiated
 * @param expiresAt          timestamp when flow expires (typically 5 minutes TTL)
 * @since 0.1.0
 */
public record FlowStateRecord(
        String stateHash,
        String providerId,
        String redirectUri,
        String targetPostLoginUrl,
        String codeVerifier,
        String nonce,
        Instant createdAt,
        Instant expiresAt
) {
    public FlowStateRecord {
        Objects.requireNonNull(stateHash, "stateHash must not be null");
        Objects.requireNonNull(providerId, "providerId must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
