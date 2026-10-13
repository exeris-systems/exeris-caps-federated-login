package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.FederationProviderAdapter;
import eu.exeris.caps.federatedlogin.api.FederationProviderRegistry;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory implementation of {@link FederationProviderRegistry}.
 *
 * @since 0.1.0
 */
public final class DefaultFederationProviderRegistry implements FederationProviderRegistry {

    private final Map<String, FederationProviderAdapter> providers = new ConcurrentHashMap<>();

    public DefaultFederationProviderRegistry() {
    }

    public DefaultFederationProviderRegistry(List<FederationProviderAdapter> initialProviders) {
        if (initialProviders != null) {
            for (FederationProviderAdapter adapter : initialProviders) {
                register(adapter);
            }
        }
    }

    @Override
    public void register(FederationProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter must not be null");
        providers.put(adapter.metadata().providerId(), adapter);
    }

    @Override
    public Optional<FederationProviderAdapter> findProvider(String providerId) {
        if (providerId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(providers.get(providerId));
    }

    @Override
    public List<FederationProviderAdapter> allProviders() {
        return List.copyOf(providers.values());
    }
}
