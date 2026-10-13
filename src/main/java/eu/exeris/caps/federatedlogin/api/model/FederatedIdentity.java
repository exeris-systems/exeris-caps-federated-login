package eu.exeris.caps.federatedlogin.api.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Standardized profile representing an identity authenticated by an external identity provider.
 *
 * @param issuer          canonical issuer URI of the provider (e.g. "https://accounts.google.com", "https://github.com")
 * @param externalSubject stable unique subject identifier assigned by the provider
 * @param email           primary email address if available
 * @param emailVerified   whether the email address has been verified by the provider
 * @param displayName     human-readable display name or username
 * @param avatarUrl       URL pointing to the user's avatar image if available
 * @param rawAttributes   unmodifiable map of raw provider claims/profile attributes
 * @since 0.1.0
 */
public record FederatedIdentity(
        String issuer,
        String externalSubject,
        String email,
        boolean emailVerified,
        String displayName,
        String avatarUrl,
        Map<String, Object> rawAttributes
) {
    public FederatedIdentity {
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");
        if (rawAttributes != null) {
            rawAttributes = Collections.unmodifiableMap(new LinkedHashMap<>(rawAttributes));
        } else {
            rawAttributes = Map.of();
        }
    }
}
