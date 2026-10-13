package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when an identity link cannot be established due to an existing binding conflict.
 *
 * @since 0.1.0
 */
public final class IdentityLinkConflictException extends FederatedLoginException {

    public IdentityLinkConflictException(String message) {
        super(message);
    }

    public IdentityLinkConflictException(String message, Throwable cause) {
        super(message, cause);
    }
}
