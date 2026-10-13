package eu.exeris.caps.federatedlogin.api.exception;

import java.util.Objects;

/**
 * Thrown at construction when required configuration is missing or malformed. The message names the
 * configuration key and never carries its value.
 *
 * @since 0.1.0
 */
public final class FederatedLoginConfigurationException extends FederatedLoginException {

    private final String key;

    public FederatedLoginConfigurationException(String key, String message) {
        super(key + ": " + message);
        this.key = Objects.requireNonNull(key, "key must not be null");
    }

    public FederatedLoginConfigurationException(String key, String message, Throwable cause) {
        super(key + ": " + message, cause);
        this.key = Objects.requireNonNull(key, "key must not be null");
    }

    /**
     * @return the configuration key the failure concerns
     */
    public String key() {
        return key;
    }
}
