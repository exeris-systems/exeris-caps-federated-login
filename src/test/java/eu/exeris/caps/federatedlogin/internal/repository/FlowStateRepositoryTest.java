package eu.exeris.caps.federatedlogin.internal.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("InMemoryFlowStateRepository Unit Tests")
class FlowStateRepositoryTest {

    @Test
    @DisplayName("flow state save, single-use atomic consumption, and replay rejection")
    void saveAndSingleUseConsumption() {
        InMemoryFlowStateRepository repository = new InMemoryFlowStateRepository();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300);

        FlowStateRecord record = new FlowStateRecord(
                "hash-123",
                "google",
                "https://app.exeris.eu/callback",
                "https://app.exeris.eu/dashboard",
                "verifier-abc",
                "nonce-xyz",
                now,
                expiresAt,
                "binding-hash"
        );

        repository.save(record);

        // First consume succeeds
        Optional<FlowStateRecord> consumed = repository.consume("hash-123", now);
        assertThat(consumed).isPresent();
        assertThat(consumed.get().providerId()).isEqualTo("google");
        assertThat(consumed.get().codeVerifier()).isEqualTo("verifier-abc");
        assertThat(consumed.get().targetPostLoginUrl()).isEqualTo("https://app.exeris.eu/dashboard");

        // Second consume (replay) returns empty
        Optional<FlowStateRecord> replayed = repository.consume("hash-123", now);
        assertThat(replayed).isEmpty();
    }

    @Test
    @DisplayName("expired flow state is rejected upon consumption")
    void expiredFlowStateRejected() {
        InMemoryFlowStateRepository repository = new InMemoryFlowStateRepository();
        Instant now = Instant.now();
        Instant expiresAt = now.minusSeconds(10); // already expired

        FlowStateRecord record = new FlowStateRecord(
                "hash-expired",
                "github",
                "https://app.exeris.eu/callback",
                null,
                "verifier-exp",
                null,
                now.minusSeconds(60),
                expiresAt,
                "binding-hash"
        );

        repository.save(record);

        Optional<FlowStateRecord> consumed = repository.consume("hash-expired", now);
        assertThat(consumed).isEmpty();
    }

    @Test
    @DisplayName("prune expired records removes expired flow states")
    void pruneExpired() {
        InMemoryFlowStateRepository repository = new InMemoryFlowStateRepository();
        Instant now = Instant.now();

        repository.save(new FlowStateRecord("hash-expired", "google", "https://cb", null, "v", null, now.minusSeconds(300), now.minusSeconds(10), "b"));
        repository.save(new FlowStateRecord("hash-live", "github", "https://cb", null, "v", null, now, now.plusSeconds(300), "b"));

        repository.pruneExpired(now);

        assertThat(repository.consume("hash-expired", now)).isEmpty();
        assertThat(repository.consume("hash-live", now)).isPresent();
    }
}
