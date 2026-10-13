package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when an identity provider cannot be resolved by identifier.
 *
 * @since 0.1.0
 */
public final class ProviderNotFoundException extends FederatedLoginException {

    private final String providerId;

    public ProviderNotFoundException(String providerId) {
        super("Federation provider not found: " + providerId);
        this.providerId = providerId;
    }

    public String providerId() {
        return providerId;
    }
}
