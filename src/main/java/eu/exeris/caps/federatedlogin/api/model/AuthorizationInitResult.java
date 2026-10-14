package eu.exeris.caps.federatedlogin.api.model;

import java.util.Objects;

/**
 * Result of initiating a federated login flow.
 *
 * @param authorizationUri the provider authorization URI to redirect the user agent to
 * @param state            the cryptographic flow state parameter
 * @param browserBinding   a one-time secret the caller must set on the initiating user agent (for
 *                         example as a {@code __Host-} cookie) and present again at the callback
 * @since 0.1.0
 */
public record AuthorizationInitResult(
        String authorizationUri,
        String state,
        String browserBinding
) {
    public AuthorizationInitResult {
        Objects.requireNonNull(authorizationUri, "authorizationUri must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(browserBinding, "browserBinding must not be null");
    }
}
