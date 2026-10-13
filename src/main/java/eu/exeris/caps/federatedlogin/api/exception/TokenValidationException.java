package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when an ID token or cryptographic credential returned by an identity provider
 * fails validation (e.g. signature, issuer mismatch, nonce assertion, or expired token).
 *
 * @since 0.1.0
 */
public final class TokenValidationException extends FederatedLoginException {

    public TokenValidationException(String message) {
        super(message);
    }

    public TokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
