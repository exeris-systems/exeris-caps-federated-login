package eu.exeris.caps.federatedlogin.internal.flow;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.federatedlogin.api.FederationProviderAdapter;
import eu.exeris.caps.federatedlogin.api.exception.InvalidStateException;
import eu.exeris.caps.federatedlogin.api.exception.ProviderNotFoundException;
import eu.exeris.caps.federatedlogin.api.model.AuthorizationInitResult;
import eu.exeris.caps.federatedlogin.api.model.CallbackExchangeCommand;
import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.FederatedLoginResult;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.api.model.ProviderMetadata;
import eu.exeris.caps.federatedlogin.internal.provider.DefaultExternalIdentityLink;
import eu.exeris.caps.federatedlogin.internal.provider.DefaultFederationProviderRegistry;
import eu.exeris.caps.federatedlogin.internal.repository.InMemoryExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.internal.repository.InMemoryFlowStateRepository;
import eu.exeris.caps.federatedlogin.spi.AuditTrailBridge;
import eu.exeris.caps.federatedlogin.spi.InMemoryOutboundCredentialStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultFederatedLoginFlow Unit Tests")
class DefaultFederatedLoginFlowTest {

    private static final class TestAuditSink implements AuditLogSink {
        final List<AuditEvent> events = new ArrayList<>();
        @Override public void emit(AuditEvent event) { events.add(event); }
        @Override public List<AuditEvent> query(eu.exeris.caps.audittrail.api.AuditQuery query) { return List.of(); }
        @Override public long count(eu.exeris.caps.audittrail.api.AuditQuery query) { return events.size(); }
    }

    private static final class DummyProviderAdapter implements FederationProviderAdapter {
        private final String providerId;
        private final String issuer;

        DummyProviderAdapter(String providerId, String issuer) {
            this.providerId = providerId;
            this.issuer = issuer;
        }

        @Override
        public ProviderMetadata metadata() {
            return new ProviderMetadata(providerId, issuer, "https://auth", "https://token", null, List.of("test"), true);
        }

        @Override
        public String buildAuthorizationUri(String clientId, String redirectUri, String state, String codeChallenge, String nonce) {
            return "https://auth?state=" + state + "&code_challenge=" + codeChallenge;
        }

        @Override
        public FederatedIdentity processExchange(ProviderExchangeRequest request) {
            return new FederatedIdentity(issuer, "dummy-sub-100", "dummy@example.com", true, "Dummy User", null, Map.of());
        }
    }

    private DefaultFederationProviderRegistry providerRegistry;
    private InMemoryFlowStateRepository flowStateRepository;
    private InMemoryExternalIdentityRepository identityRepository;
    private DefaultExternalIdentityLink externalIdentityLink;
    private InMemoryOutboundCredentialStore credentialStore;
    private TestAuditSink auditSink;
    private DefaultFederatedLoginFlow flow;

    @BeforeEach
    void setUp() {
        providerRegistry = new DefaultFederationProviderRegistry();
        providerRegistry.register(new DummyProviderAdapter("test-provider", "https://test.provider.com"));

        flowStateRepository = new InMemoryFlowStateRepository();
        identityRepository = new InMemoryExternalIdentityRepository();
        auditSink = new TestAuditSink();
        AuditTrailBridge auditTrail = new AuditTrailBridge(auditSink);
        externalIdentityLink = new DefaultExternalIdentityLink(identityRepository, auditTrail);

        credentialStore = new InMemoryOutboundCredentialStore();
        credentialStore.register("test-provider", "client-id-1", "client-secret-1");

        flow = new DefaultFederatedLoginFlow(
                providerRegistry,
                flowStateRepository,
                externalIdentityLink,
                credentialStore,
                null,
                null,
                auditTrail,
                Duration.ofMinutes(5)
        );
    }

    @Test
    @DisplayName("initiateLogin persists encrypted state and produces authorization result")
    void initiateLogin() {
        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/welcome"
        );

        assertThat(initResult.state()).isNotBlank();
        assertThat(initResult.authorizationUri()).contains("https://auth?state=" + initResult.state());

        String hash = PkceGenerator.computeStateHash(initResult.state());
        assertThat(flowStateRepository.consume(hash, java.time.Instant.now())).isPresent();
    }

    @Test
    @DisplayName("Pre-Account Takeover Defense: unlinked identity returns empty local subject and isNewLink=true")
    void unlinkedCallbackProcessing() {
        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/welcome"
        );

        CallbackExchangeCommand command = new CallbackExchangeCommand(
                "test-provider",
                "auth-code-test",
                initResult.state(),
                "https://app.exeris.eu/cb"
        );

        FederatedLoginResult result = flow.processCallback(command);

        assertThat(result.linkedLocalSubjectId()).isEmpty();
        assertThat(result.isNewLink()).isTrue();
        assertThat(result.targetPostLoginUrl()).isEqualTo("https://app.exeris.eu/welcome");
        assertThat(result.identity().externalSubject()).isEqualTo("dummy-sub-100");
    }

    @Test
    @DisplayName("already linked identity returns local subject and isNewLink=false")
    void linkedCallbackProcessing() {
        UUID existingSubject = UUID.randomUUID();
        externalIdentityLink.link(existingSubject, "https://test.provider.com", "dummy-sub-100", "dummy@example.com", true, Map.of());

        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/app"
        );

        CallbackExchangeCommand command = new CallbackExchangeCommand(
                "test-provider",
                "code-xyz",
                initResult.state(),
                "https://app.exeris.eu/cb"
        );

        FederatedLoginResult result = flow.processCallback(command);

        assertThat(result.linkedLocalSubjectId()).contains(existingSubject);
        assertThat(result.isNewLink()).isFalse();
        assertThat(result.targetPostLoginUrl()).isEqualTo("https://app.exeris.eu/app");
    }

    @Test
    @DisplayName("replay attack prevention: single-use state consumption rejects second callback")
    void replayAttackRejection() {
        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        CallbackExchangeCommand command = new CallbackExchangeCommand(
                "test-provider",
                "code-1",
                initResult.state(),
                "https://app.exeris.eu/cb"
        );

        // First callback succeeds
        flow.processCallback(command);

        // Replay attempt with same state must fail
        assertThatThrownBy(() -> flow.processCallback(command))
                .isInstanceOf(InvalidStateException.class)
                .hasMessageContaining("invalid, expired, or already consumed");
    }

    @Test
    @DisplayName("tampered state token is rejected")
    void tamperedStateRejection() {
        flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        CallbackExchangeCommand tamperedCommand = new CallbackExchangeCommand(
                "test-provider",
                "code-1",
                "tampered-state-token-xyz",
                "https://app.exeris.eu/cb"
        );

        assertThatThrownBy(() -> flow.processCallback(tamperedCommand))
                .isInstanceOf(InvalidStateException.class);
    }

    @Test
    @DisplayName("redirect URI mismatch between initiate and callback is rejected")
    void redirectUriMismatchRejection() {
        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        CallbackExchangeCommand mismatchCommand = new CallbackExchangeCommand(
                "test-provider",
                "code-1",
                initResult.state(),
                "https://app.exeris.eu/different-cb"
        );

        assertThatThrownBy(() -> flow.processCallback(mismatchCommand))
                .isInstanceOf(InvalidStateException.class)
                .hasMessageContaining("Redirect URI mismatch");
    }

    @Test
    @DisplayName("provider mismatch between initiate and callback is rejected")
    void providerMismatchRejection() {
        providerRegistry.register(new DummyProviderAdapter("other-provider", "https://other.com"));
        credentialStore.register("other-provider", "client-2", "secret-2");

        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        CallbackExchangeCommand mismatchCommand = new CallbackExchangeCommand(
                "other-provider",
                "code-1",
                initResult.state(),
                "https://app.exeris.eu/cb"
        );

        assertThatThrownBy(() -> flow.processCallback(mismatchCommand))
                .isInstanceOf(InvalidStateException.class)
                .hasMessageContaining("Provider mismatch");
    }

    @Test
    @DisplayName("expired flow state in callback is rejected")
    void expiredFlowCallbackRejection() throws Exception {
        DefaultFederatedLoginFlow shortLivedFlow = new DefaultFederatedLoginFlow(
                providerRegistry,
                flowStateRepository,
                externalIdentityLink,
                credentialStore,
                null,
                null,
                null,
                Duration.ofMillis(1) // expires immediately
        );

        AuthorizationInitResult initResult = shortLivedFlow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        Thread.sleep(10); // ensure expiry passes

        CallbackExchangeCommand command = new CallbackExchangeCommand(
                "test-provider",
                "code-1",
                initResult.state(),
                "https://app.exeris.eu/cb"
        );

        assertThatThrownBy(() -> shortLivedFlow.processCallback(command))
                .isInstanceOf(InvalidStateException.class)
                .hasMessageContaining("invalid, expired, or already consumed");
    }

    @Test
    @DisplayName("unknown provider throws ProviderNotFoundException")
    void unknownProvider() {
        assertThatThrownBy(() -> flow.initiateLogin("unknown", "https://cb", null))
                .isInstanceOf(ProviderNotFoundException.class);
    }

    @Test
    @DisplayName("blank providerId or redirectUri in initiateLogin throws IllegalArgumentException")
    void blankInputValidation() {
        assertThatThrownBy(() -> flow.initiateLogin("", "https://cb", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> flow.initiateLogin("test-provider", "   ", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("mismatch on provider or redirectUri emits audit event with reason")
    void mismatchAuditEmissions() {
        AuthorizationInitResult initResult = flow.initiateLogin(
                "test-provider",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/home"
        );

        CallbackExchangeCommand mismatchRedirect = new CallbackExchangeCommand(
                "test-provider",
                "code-1",
                initResult.state(),
                "https://app.exeris.eu/wrong-cb"
        );

        assertThatThrownBy(() -> flow.processCallback(mismatchRedirect))
                .isInstanceOf(InvalidStateException.class);

        assertThat(auditSink.events)
                .anyMatch(e -> e.action().equals("FEDERATED_LOGIN_REJECTED")
                        && "redirect_uri_mismatch".equals(e.details().get("reason")));
    }
}
