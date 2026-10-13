package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when an HTTP or network error occurs while communicating with an external identity provider,
 * or when the provider returns an unexpected or error response during code exchange.
 *
 * @since 0.1.0
 */
public final class ProviderCommunicationException extends FederatedLoginException {

    private final int statusCode;

    public ProviderCommunicationException(String message) {
        super(message);
        this.statusCode = 0;
    }

    public ProviderCommunicationException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = 0;
    }

    public ProviderCommunicationException(String message, int statusCode) {
        super(message + " (HTTP " + statusCode + ")");
        this.statusCode = statusCode;
    }

    public int statusCode() {
        return statusCode;
    }
}
