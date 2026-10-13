package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when the cryptographic flow state token is invalid, expired, tampered, or already consumed.
 *
 * @since 0.1.0
 */
public class InvalidStateException extends FederatedLoginException {

    public InvalidStateException(String message) {
        super(message);
    }

    public InvalidStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
