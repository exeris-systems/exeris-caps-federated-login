package eu.exeris.caps.federatedlogin;

import eu.exeris.caps.federatedlogin.api.ExternalIdentityLink;
import eu.exeris.caps.federatedlogin.api.FederatedLoginFlow;
import eu.exeris.caps.federatedlogin.api.FederationProviderRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

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
}
