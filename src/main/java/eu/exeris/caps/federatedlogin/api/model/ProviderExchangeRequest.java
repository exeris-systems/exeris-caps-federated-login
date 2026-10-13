package eu.exeris.caps.federatedlogin.api.model;

import eu.exeris.kernel.spi.http.HttpClientEngine;
import eu.exeris.kernel.spi.security.identity.TokenValidator;

import java.util.Objects;

/**
 * Context parameters passed to {@link eu.exeris.caps.federatedlogin.api.FederationProviderAdapter#processExchange}
 * during authorization code exchange.
 *
 * @param code           the authorization code received from the callback
 * @param redirectUri    the callback redirect URI used in the initiation request
 * @param codeVerifier   the high-entropy RFC 7636 PKCE code verifier, or null if PKCE was not used
 * @param nonce          the cryptographic OIDC nonce, or null if not used
 * @param clientId       the client identifier registered with the identity provider
 * @param clientSecret   the client secret registered with the identity provider
 * @param httpClient     the kernel HTTP client engine for outbound requests
 * @param tokenValidator the kernel token validator for OIDC ID token signature verification
 * @since 0.1.0
 */
public record ProviderExchangeRequest(
        String code,
        String redirectUri,
        String codeVerifier,
        String nonce,
        String clientId,
        String clientSecret,
        HttpClientEngine httpClient,
        TokenValidator tokenValidator
) {
    public ProviderExchangeRequest {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientSecret, "clientSecret must not be null");
    }
}
