package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when a redirect URI is not on the configured allow-list for its provider, or a post-login
 * target is neither a safe relative path nor on an allow-listed origin. The message names the rule that
 * failed and never echoes the rejected value.
 *
 * @since 0.1.0
 */
public final class InvalidRedirectException extends FederatedLoginException {

    public InvalidRedirectException(String message) {
        super(message);
    }
}
