package eu.exeris.caps.federatedlogin;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.federatedlogin.api.ExternalIdentityLink;
import eu.exeris.caps.federatedlogin.api.FederatedLoginFlow;
import eu.exeris.caps.federatedlogin.api.FederationProviderRegistry;
import eu.exeris.caps.federatedlogin.internal.flow.DefaultFederatedLoginFlow;
import eu.exeris.caps.federatedlogin.internal.provider.DefaultExternalIdentityLink;
import eu.exeris.caps.federatedlogin.internal.provider.DefaultFederationProviderRegistry;
import eu.exeris.caps.federatedlogin.internal.provider.GitHubFederationProvider;
import eu.exeris.caps.federatedlogin.internal.provider.GoogleFederationProvider;
import eu.exeris.caps.federatedlogin.internal.repository.ExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.internal.repository.FlowStateRepository;
import eu.exeris.caps.federatedlogin.internal.repository.InMemoryExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.internal.repository.InMemoryFlowStateRepository;
import eu.exeris.caps.federatedlogin.internal.repository.PostgresExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.internal.repository.PostgresFlowStateRepository;
import eu.exeris.caps.federatedlogin.spi.AuditTrailBridge;
import eu.exeris.caps.federatedlogin.spi.InMemoryOutboundCredentialStore;
import eu.exeris.caps.federatedlogin.spi.OutboundCredentialStore;
import eu.exeris.kernel.spi.http.HttpClientEngine;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.security.identity.TokenValidator;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-federated-login}.
 *
 * <p>Provides Layer 5 Domain Primitives (ADR-099, Capability z):
 * <ul>
 *   <li>{@link FederatedLoginFlow} (OAuth 2.0 PKCE, state/nonce validation, OIDC ID-token verification)</li>
 *   <li>{@link ExternalIdentityLink} (binding provider identities to local subjects with conflict detection)</li>
 *   <li>{@link FederationProviderRegistry} (extensible provider registry with built-in Google and GitHub adapters)</li>
 * </ul>
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = FederatedLoginFlow.class, version = "0.1.0")
@Provides(service = ExternalIdentityLink.class, version = "0.1.0")
@Provides(service = FederationProviderRegistry.class, version = "0.1.0")
@Requires(service = OutboundCredentialStore.class, versionRange = "[0.1.0,0.2.0)", optional = true)
@Requires(service = HttpClientEngine.class, optional = true)
@Requires(service = TokenValidator.class, optional = true)
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[0.1.0,0.2.0)", optional = true)
public final class FederatedLoginModule implements CapabilityLifecycleHooks {

    private final FederatedLoginFlow federatedLoginFlow;
    private final ExternalIdentityLink externalIdentityLink;
    private final FederationProviderRegistry providerRegistry;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition runtime.
     * Initializes in-memory test doubles and default built-in providers.
     */
    public FederatedLoginModule() {
        this(
                new InMemoryFlowStateRepository(),
                new InMemoryExternalIdentityRepository(),
                new DefaultFederationProviderRegistry(List.of(new GoogleFederationProvider(), new GitHubFederationProvider())),
                new InMemoryOutboundCredentialStore(),
                null,
                null,
                null
        );
    }

    /**
     * Constructor wiring with {@link TransactionalExecutor} for PostgreSQL persistence.
     */
    public FederatedLoginModule(
            TransactionalExecutor tx,
            OutboundCredentialStore credentialStore,
            HttpClientEngine httpClient,
            TokenValidator tokenValidator,
            AuditLogSink auditLogSink
    ) {
        this(
                tx != null ? new PostgresFlowStateRepository(tx) : new InMemoryFlowStateRepository(),
                tx != null ? new PostgresExternalIdentityRepository(tx) : new InMemoryExternalIdentityRepository(),
                new DefaultFederationProviderRegistry(List.of(new GoogleFederationProvider(), new GitHubFederationProvider())),
                credentialStore != null ? credentialStore : new InMemoryOutboundCredentialStore(),
                httpClient,
                tokenValidator,
                auditLogSink != null ? new AuditTrailBridge(auditLogSink) : null
        );
    }

    /**
     * Full custom wiring constructor; package-private because its parameters are internal types.
     */
    FederatedLoginModule(
            FlowStateRepository flowStateRepository,
            ExternalIdentityRepository identityRepository,
            FederationProviderRegistry providerRegistry,
            OutboundCredentialStore credentialStore,
            HttpClientEngine httpClient,
            TokenValidator tokenValidator,
            AuditTrailBridge auditTrail
    ) {
        Objects.requireNonNull(flowStateRepository, "flowStateRepository must not be null");
        Objects.requireNonNull(identityRepository, "identityRepository must not be null");
        Objects.requireNonNull(providerRegistry, "providerRegistry must not be null");
        Objects.requireNonNull(credentialStore, "credentialStore must not be null");

        this.providerRegistry = providerRegistry;
        this.externalIdentityLink = new DefaultExternalIdentityLink(identityRepository, auditTrail);
        this.federatedLoginFlow = new DefaultFederatedLoginFlow(
                providerRegistry,
                flowStateRepository,
                this.externalIdentityLink,
                credentialStore,
                httpClient,
                tokenValidator,
                auditTrail
        );
    }

    public FederatedLoginFlow federatedLoginFlow() {
        return federatedLoginFlow;
    }

    public ExternalIdentityLink externalIdentityLink() {
        return externalIdentityLink;
    }

    public FederationProviderRegistry providerRegistry() {
        return providerRegistry;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
