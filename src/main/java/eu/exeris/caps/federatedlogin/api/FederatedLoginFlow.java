package eu.exeris.caps.federatedlogin.api;

import eu.exeris.caps.federatedlogin.api.model.AuthorizationInitResult;
import eu.exeris.caps.federatedlogin.api.model.CallbackExchangeCommand;
import eu.exeris.caps.federatedlogin.api.model.FederatedLoginResult;

/**
 * High-level orchestrator for federated authentication flows.
 *
 * <p>Handles:
 * <ul>
 *   <li>Authorization flow initiation (PKCE generation, state and nonce generation, encrypted storage)</li>
 *   <li>Callback processing (single-use state consumption, code exchange, ID token validation, and link resolution)</li>
 * </ul>
 *
 * @since 0.1.0
 */
public interface FederatedLoginFlow {

    /**
     * Initiates a federated login flow with the specified provider.
     *
     * @param providerId         identifier of the provider (e.g. "google", "github")
     * @param redirectUri        registered redirect URI for callback
     * @param targetPostLoginUrl application URL to navigate the user to after successful sign-in
     * @return the authorization redirect URI and anti-forgery state token
     */
    AuthorizationInitResult initiateLogin(String providerId, String redirectUri, String targetPostLoginUrl);

    /**
     * Processes the callback from the identity provider after user authorization.
     *
     * @param command callback parameters containing code and state
     * @return the login result containing verified identity and linked local subject (if bound)
     */
    FederatedLoginResult processCallback(CallbackExchangeCommand command);
}
