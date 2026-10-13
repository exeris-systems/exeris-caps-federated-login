package eu.exeris.caps.federatedlogin.internal.flow;

import eu.exeris.caps.federatedlogin.api.ExternalIdentityLink;
import eu.exeris.caps.federatedlogin.api.FederatedLoginFlow;
import eu.exeris.caps.federatedlogin.api.FederationProviderAdapter;
import eu.exeris.caps.federatedlogin.api.FederationProviderRegistry;
import eu.exeris.caps.federatedlogin.api.exception.InvalidStateException;
import eu.exeris.caps.federatedlogin.api.exception.ProviderCommunicationException;
import eu.exeris.caps.federatedlogin.api.model.AuthorizationInitResult;
import eu.exeris.caps.federatedlogin.api.model.CallbackExchangeCommand;
import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.FederatedLoginResult;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.internal.repository.FlowStateRecord;
import eu.exeris.caps.federatedlogin.internal.repository.FlowStateRepository;
import eu.exeris.caps.federatedlogin.spi.AuditTrailBridge;
import eu.exeris.caps.federatedlogin.spi.OutboundCredentialStore;
import eu.exeris.kernel.spi.http.HttpClientEngine;
import eu.exeris.kernel.spi.security.identity.TokenValidator;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link FederatedLoginFlow}.
 *
 * <p>Orchestrates PKCE and flow generation, encrypted flow state storage, single-use atomic
 * consumption, provider token exchange, identity validation, and pre-account takeover protection.
 *
 * @since 0.1.0
 */
public final class DefaultFederatedLoginFlow implements FederatedLoginFlow {

    public static final Duration DEFAULT_FLOW_TTL = Duration.ofMinutes(5);

    private final FederationProviderRegistry providerRegistry;
    private final FlowStateRepository flowStateRepository;
    private final ExternalIdentityLink externalIdentityLink;
    private final OutboundCredentialStore credentialStore;
    private final HttpClientEngine httpClient;
    private final TokenValidator tokenValidator;
    private final AuditTrailBridge auditTrail;
    private final Duration flowTtl;

    public DefaultFederatedLoginFlow(
            FederationProviderRegistry providerRegistry,
            FlowStateRepository flowStateRepository,
            ExternalIdentityLink externalIdentityLink,
            OutboundCredentialStore credentialStore,
            HttpClientEngine httpClient,
            TokenValidator tokenValidator,
            AuditTrailBridge auditTrail
    ) {
        this(providerRegistry, flowStateRepository, externalIdentityLink, credentialStore,
                httpClient, tokenValidator, auditTrail, DEFAULT_FLOW_TTL);
    }

    public DefaultFederatedLoginFlow(
            FederationProviderRegistry providerRegistry,
            FlowStateRepository flowStateRepository,
            ExternalIdentityLink externalIdentityLink,
            OutboundCredentialStore credentialStore,
            HttpClientEngine httpClient,
            TokenValidator tokenValidator,
            AuditTrailBridge auditTrail,
            Duration flowTtl
    ) {
        this.providerRegistry = Objects.requireNonNull(providerRegistry, "providerRegistry must not be null");
        this.flowStateRepository = Objects.requireNonNull(flowStateRepository, "flowStateRepository must not be null");
        this.externalIdentityLink = Objects.requireNonNull(externalIdentityLink, "externalIdentityLink must not be null");
        this.credentialStore = Objects.requireNonNull(credentialStore, "credentialStore must not be null");
        this.httpClient = httpClient;
        this.tokenValidator = tokenValidator;
        this.auditTrail = auditTrail;
        this.flowTtl = flowTtl != null ? flowTtl : DEFAULT_FLOW_TTL;
    }

    @Override
    public AuthorizationInitResult initiateLogin(String providerId, String redirectUri, String targetPostLoginUrl) {
        Objects.requireNonNull(providerId, "providerId must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        if (providerId.isBlank()) {
            throw new IllegalArgumentException("providerId must not be blank");
        }
        if (redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri must not be blank");
        }

        FederationProviderAdapter adapter = providerRegistry.getProvider(providerId);

        OutboundCredentialStore.ProviderClientCredentials credentials = credentialStore.getCredentials(providerId)
                .orElseThrow(() -> new ProviderCommunicationException("No client credentials registered for provider: " + providerId));

        String state = PkceGenerator.generateState();
        String nonce = PkceGenerator.generateNonce();
        String codeVerifier = adapter.metadata().supportsPkce() ? PkceGenerator.generateCodeVerifier() : null;
        String codeChallenge = codeVerifier != null ? PkceGenerator.generateCodeChallenge(codeVerifier) : null;

        String stateHash = PkceGenerator.computeStateHash(state);
        Instant now = Instant.now();
        Instant expiresAt = now.plus(flowTtl);

        FlowStateRecord record = new FlowStateRecord(
                stateHash,
                providerId,
                redirectUri,
                targetPostLoginUrl,
                codeVerifier,
                nonce,
                now,
                expiresAt
        );

        flowStateRepository.save(record);

        String authorizationUri = adapter.buildAuthorizationUri(
                credentials.clientId(),
                redirectUri,
                state,
                codeChallenge,
                nonce
        );

        if (auditTrail != null) {
            auditTrail.emit("FEDERATED_LOGIN_INITIATED", "system", Map.of(
                    "provider_id", providerId,
                    "redirect_uri", redirectUri
            ));
        }

        return new AuthorizationInitResult(authorizationUri, state);
    }

    @Override
    public FederatedLoginResult processCallback(CallbackExchangeCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        String stateHash = PkceGenerator.computeStateHash(command.state());
        Instant now = Instant.now();

        // 1. Single-use atomic consumption of flow state
        Optional<FlowStateRecord> consumed = flowStateRepository.consume(stateHash, now);
        if (consumed.isEmpty()) {
            if (auditTrail != null) {
                auditTrail.emit("FEDERATED_LOGIN_REJECTED", "system", Map.of(
                        "provider_id", command.providerId(),
                        "reason", "invalid_or_consumed_state"
                ));
            }
            throw new InvalidStateException("Federated flow state is invalid, expired, or already consumed");
        }

        FlowStateRecord flow = consumed.get();

        // 2. Validate provider matching
        if (!flow.providerId().equals(command.providerId())) {
            if (auditTrail != null) {
                auditTrail.emit("FEDERATED_LOGIN_REJECTED", "system", Map.of(
                        "provider_id", command.providerId(),
                        "reason", "provider_mismatch"
                ));
            }
            throw new InvalidStateException("Provider mismatch in callback: expected " + flow.providerId()
                    + " but received " + command.providerId());
        }

        // 3. Validate redirect URI matching
        if (!flow.redirectUri().equals(command.redirectUri())) {
            if (auditTrail != null) {
                auditTrail.emit("FEDERATED_LOGIN_REJECTED", "system", Map.of(
                        "provider_id", command.providerId(),
                        "reason", "redirect_uri_mismatch"
                ));
            }
            throw new InvalidStateException("Redirect URI mismatch in callback: expected " + flow.redirectUri()
                    + " but received " + command.redirectUri());
        }

        // 4. Resolve adapter and credentials
        FederationProviderAdapter adapter = providerRegistry.getProvider(command.providerId());
        OutboundCredentialStore.ProviderClientCredentials credentials = credentialStore.getCredentials(command.providerId())
                .orElseThrow(() -> new ProviderCommunicationException("No client credentials registered for provider: " + command.providerId()));

        // 5. Exchange code for identity
        ProviderExchangeRequest exchangeRequest = new ProviderExchangeRequest(
                command.code(),
                command.redirectUri(),
                flow.codeVerifier(),
                flow.nonce(),
                credentials.clientId(),
                credentials.clientSecret(),
                httpClient,
                tokenValidator
        );

        FederatedIdentity identity = adapter.processExchange(exchangeRequest);

        // 6. Pre-account takeover protection (ADR-099): link look up strictly by (issuer, externalSubject)
        Optional<UUID> linkedSubjectId = externalIdentityLink.findLinkedSubject(identity.issuer(), identity.externalSubject());

        FederatedLoginResult result = linkedSubjectId
                .map(uuid -> FederatedLoginResult.linked(uuid, identity, flow.targetPostLoginUrl()))
                .orElseGet(() -> FederatedLoginResult.unlinked(identity, flow.targetPostLoginUrl()));

        if (auditTrail != null) {
            auditTrail.emit("FEDERATED_LOGIN_SUCCESS", linkedSubjectId.orElse(null), Map.of(
                    "issuer", identity.issuer(),
                    "external_subject", identity.externalSubject(),
                    "is_new_link", result.isNewLink(),
                    "provider_id", command.providerId()
            ));
        }

        return result;
    }
}
