package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Base exception for all federated login capability failures.
 *
 * @since 0.1.0
 */
public class FederatedLoginException extends RuntimeException {

    public FederatedLoginException(String message) {
        super(message);
    }

    public FederatedLoginException(String message, Throwable cause) {
        super(message, cause);
    }
}
