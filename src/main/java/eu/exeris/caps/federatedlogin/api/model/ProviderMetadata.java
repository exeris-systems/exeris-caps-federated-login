package eu.exeris.caps.federatedlogin.api.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Metadata descriptor for a federated identity provider.
 *
 * @param providerId             identifier (e.g. "google", "github")
 * @param issuer                 canonical issuer URI
 * @param authorizationEndpoint  authorization endpoint URL
 * @param tokenEndpoint          token exchange endpoint URL
 * @param userinfoEndpoint       userinfo endpoint URL, or null if not applicable
 * @param scopes                 default scopes requested during authorization
 * @param supportsPkce           whether this provider supports RFC 7636 PKCE
 * @since 0.1.0
 */
public record ProviderMetadata(
        String providerId,
        String issuer,
        String authorizationEndpoint,
        String tokenEndpoint,
        String userinfoEndpoint,
        List<String> scopes,
        boolean supportsPkce
) {
    public ProviderMetadata {
        Objects.requireNonNull(providerId, "providerId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint must not be null");
        Objects.requireNonNull(tokenEndpoint, "tokenEndpoint must not be null");
        if (scopes != null) {
            scopes = Collections.unmodifiableList(List.copyOf(scopes));
        } else {
            scopes = List.of();
        }
    }
}
