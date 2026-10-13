package eu.exeris.caps.federatedlogin;

import eu.exeris.caps.federatedlogin.api.ExternalIdentityLink;
import eu.exeris.caps.federatedlogin.api.FederatedLoginFlow;
import eu.exeris.caps.federatedlogin.api.FederationProviderRegistry;
import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginConfigurationException;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("FederatedLoginModule Unit and Lifecycle Tests")
class FederatedLoginModuleTest {

    @Test
    @DisplayName("module lifecycle transitions through initialize, ready, drain, terminate")
    void lifecycleTransitions() throws Exception {
        FederatedLoginModule module = new FederatedLoginModule();

        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        assertThat(module.isReady()).isFalse();

        module.ready();
        assertThat(module.isReady()).isTrue();

        module.drain(Duration.ofSeconds(5));
        assertThat(module.isReady()).isFalse();

        module.terminate();
        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();
    }

    @Test
    @DisplayName("module exports non-null services with built-in providers registered")
    void moduleServicesExported() {
        FederatedLoginModule module = new FederatedLoginModule();

        FederatedLoginFlow flow = module.federatedLoginFlow();
        ExternalIdentityLink link = module.externalIdentityLink();
        FederationProviderRegistry registry = module.providerRegistry();

        assertThat(flow).isNotNull();
        assertThat(link).isNotNull();
        assertThat(registry).isNotNull();

        assertThat(registry.findProvider("google")).isPresent();
        assertThat(registry.findProvider("github")).isPresent();
    }

    @Test
    @DisplayName("PostgreSQL wiring without a flow-state keyring fails at construction")
    void postgresWiringRequiresKeyring() {
        TransactionalExecutor tx = new TransactionalExecutor() {
            @Override public void execute(TransactionalWork work) { }
            @Override public void executeManaged(TransactionalWork work) { }
            @Override public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) { }
            @Override public <T> T query(Function<PersistenceConnection, T> query) { return null; }
        };

        assertThatThrownBy(() -> new FederatedLoginModule(Map.of(), tx, null, null, null, null))
                .isInstanceOf(FederatedLoginConfigurationException.class)
                .hasMessageContaining("EXERIS_FEDERATED_LOGIN_STATE_KEYS");

        FederatedLoginModule module = new FederatedLoginModule(
                Map.of("EXERIS_FEDERATED_LOGIN_STATE_KEYS", "k1:" + Base64.getEncoder().encodeToString(new byte[32])),
                tx, null, null, null, null);
        assertThat(module.federatedLoginFlow()).isNotNull();
    }
}
