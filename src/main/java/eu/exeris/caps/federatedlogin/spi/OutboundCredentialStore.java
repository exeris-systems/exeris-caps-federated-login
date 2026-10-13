package eu.exeris.caps.federatedlogin.spi;

import java.util.Optional;

/**
 * SPI for resolving OAuth/OIDC client credentials per provider identifier.
 *
 * @since 0.1.0
 */
public interface OutboundCredentialStore {

    /**
     * Resolves the client ID and client secret for the specified provider ID.
     *
     * @param providerId the provider identifier (e.g. "google", "github")
     * @return client credentials if configured, otherwise {@link Optional#empty()}
     */
    Optional<ProviderClientCredentials> getCredentials(String providerId);

    /**
     * Carrier for client identifier and client secret.
     *
     * @param clientId     OAuth 2.0 client ID
     * @param clientSecret OAuth 2.0 client secret
     */
    record ProviderClientCredentials(String clientId, String clientSecret) {
        public ProviderClientCredentials {
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("clientId must not be null or blank");
            }
            if (clientSecret == null || clientSecret.isBlank()) {
                throw new IllegalArgumentException("clientSecret must not be null or blank");
            }
        }
    }
}
