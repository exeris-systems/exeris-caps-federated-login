package eu.exeris.caps.federatedlogin.spi;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory test double and standalone implementation of {@link OutboundCredentialStore}.
 *
 * @since 0.1.0
 */
public final class InMemoryOutboundCredentialStore implements OutboundCredentialStore {

    private final Map<String, ProviderClientCredentials> store = new ConcurrentHashMap<>();

    public InMemoryOutboundCredentialStore() {
    }

    public InMemoryOutboundCredentialStore(Map<String, ProviderClientCredentials> initialCredentials) {
        if (initialCredentials != null) {
            this.store.putAll(initialCredentials);
        }
    }

    /**
     * Registers client credentials for a provider.
     *
     * @param providerId   the provider identifier
     * @param clientId     client ID
     * @param clientSecret client secret
     * @return this store for chaining
     */
    public InMemoryOutboundCredentialStore register(String providerId, String clientId, String clientSecret) {
        Objects.requireNonNull(providerId, "providerId must not be null");
        store.put(providerId, new ProviderClientCredentials(clientId, clientSecret));
        return this;
    }

    @Override
    public Optional<ProviderClientCredentials> getCredentials(String providerId) {
        if (providerId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(store.get(providerId));
    }
}
