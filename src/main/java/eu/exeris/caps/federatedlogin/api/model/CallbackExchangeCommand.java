package eu.exeris.caps.federatedlogin.api.model;

import java.util.Objects;

/**
 * Command carrying the callback exchange parameters from the provider redirect.
 *
 * @param providerId   identifier of the federated identity provider (e.g. "google", "github")
 * @param code         the authorization code received from the identity provider
 * @param state        the state token returned by the identity provider
 * @param redirectUri  the redirect URI that was registered and used in the initiation request
 * @param browserBinding the value the user agent presents, set from {@code AuthorizationInitResult.browserBinding()};
 *                     a callback from a user agent that does not hold it is rejected
 * @since 0.1.0
 */
public record CallbackExchangeCommand(
        String providerId,
        String code,
        String state,
        String redirectUri,
        String browserBinding
) {
    public CallbackExchangeCommand {
        Objects.requireNonNull(providerId, "providerId must not be null");
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(browserBinding, "browserBinding must not be null");
    }
}
