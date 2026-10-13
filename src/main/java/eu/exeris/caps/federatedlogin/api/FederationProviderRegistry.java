package eu.exeris.caps.federatedlogin.api;

import eu.exeris.caps.federatedlogin.api.exception.ProviderNotFoundException;

import java.util.List;
import java.util.Optional;

/**
 * Registry managing available {@link FederationProviderAdapter} instances.
 *
 * @since 0.1.0
 */
public interface FederationProviderRegistry {

    /**
     * Registers a new provider adapter. Replaces any adapter previously registered with the same providerId.
     *
     * @param adapter the adapter to register; must not be {@code null}
     */
    void register(FederationProviderAdapter adapter);

    /**
     * Finds a provider adapter by provider identifier.
     *
     * @param providerId the provider ID (e.g. "google", "github")
     * @return provider adapter if registered, empty otherwise
     */
    Optional<FederationProviderAdapter> findProvider(String providerId);

    /**
     * Returns the provider adapter by provider ID or throws {@link ProviderNotFoundException}.
     *
     * @param providerId the provider ID
     * @return provider adapter
     * @throws ProviderNotFoundException if no provider is registered with that ID
     */
    default FederationProviderAdapter getProvider(String providerId) {
        return findProvider(providerId)
                .orElseThrow(() -> new ProviderNotFoundException(providerId));
    }

    /**
     * Returns an unmodifiable list of all registered provider adapters.
     *
     * @return list of provider adapters
     */
    List<FederationProviderAdapter> allProviders();
}
