package eu.exeris.caps.federatedlogin.api.model;

import java.util.Objects;

/**
 * Result of initiating a federated login flow.
 *
 * @param authorizationUri the provider authorization URI to redirect the user agent to
 * @param state            the cryptographic flow state parameter
 * @since 0.1.0
 */
public record AuthorizationInitResult(
        String authorizationUri,
        String state
) {
    public AuthorizationInitResult {
        Objects.requireNonNull(authorizationUri, "authorizationUri must not be null");
        Objects.requireNonNull(state, "state must not be null");
    }
}
