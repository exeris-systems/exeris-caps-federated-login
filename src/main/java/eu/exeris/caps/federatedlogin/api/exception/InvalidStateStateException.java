package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Alias exception matching the implementation plan specification for flow state validation failure.
 *
 * @since 0.1.0
 */
public final class InvalidStateStateException extends InvalidStateException {

    public InvalidStateStateException(String message) {
        super(message);
    }

    public InvalidStateStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
