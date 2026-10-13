package eu.exeris.caps.federatedlogin.api;

import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.api.model.ProviderMetadata;

/**
 * Public driver SPI for identity provider protocol integrations (e.g. Google OIDC, GitHub OAuth 2.0).
 *
 * @since 0.1.0
 */
public interface FederationProviderAdapter {

    /**
     * Returns provider descriptor metadata including endpoints and supported capabilities.
     *
     * @return provider metadata; never {@code null}
     */
    ProviderMetadata metadata();

    /**
     * Builds the authorization redirect URI for initiating the OAuth 2.0 / OIDC flow.
     *
     * @param clientId      registered client ID
     * @param redirectUri   callback redirect URI
     * @param state         anti-forgery state parameter
     * @param codeChallenge RFC 7636 PKCE S256 code challenge (nullable if not supported)
     * @param nonce         cryptographic nonce for OIDC (nullable if not supported)
     * @return formatted authorization URI
     */
    String buildAuthorizationUri(String clientId, String redirectUri, String state, String codeChallenge, String nonce);

    /**
     * Executes the code exchange and identity profile retrieval against the provider.
     *
     * @param request exchange parameters and engine handles
     * @return standardized federated identity
     */
    FederatedIdentity processExchange(ProviderExchangeRequest request);
}
