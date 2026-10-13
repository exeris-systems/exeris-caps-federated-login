package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.api.exception.FlowStateUnreadableException;
import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;
import eu.exeris.caps.federatedlogin.internal.crypto.FlowStateCrypto;
import eu.exeris.caps.federatedlogin.internal.crypto.FlowStateKeyring;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs the repositories against a real PostgreSQL started by Testcontainers. It needs a Docker daemon and
 * fails when there is none: the SQL ({@code DELETE ... RETURNING}, {@code ON CONFLICT}) is verified only
 * here, so a run that cannot start the database must not pass.
 */
@Testcontainers(disabledWithoutDocker = false)
@DisplayName("PostgresFederatedLogin PostgreSQL Integration Tests")
class PostgresFederatedLoginLiveIT {

    private static final String KEY_RING_A = "k1:" + Base64.getEncoder().encodeToString(new byte[32]);
    private static final String KEY_RING_OTHER = "k9:" + Base64.getEncoder().encodeToString(filled(5));

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static Connection jdbcConn;
    private static TransactionalExecutor tx;
    private static PostgresFlowStateRepository flowStateRepo;
    private static PostgresExternalIdentityRepository identityRepo;

    private static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static PostgresFlowStateRepository flowRepo(String keyring) {
        return new PostgresFlowStateRepository(tx, new FlowStateCrypto(FlowStateKeyring.parse("it", keyring)));
    }

    @BeforeAll
    static void setUpDatabase() throws Exception {
        jdbcConn = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        try (Statement stmt = jdbcConn.createStatement();
             InputStream is = PostgresFederatedLoginLiveIT.class.getResourceAsStream("/schema/federated-login-schema.sql")) {
            assertThat(is).as("schema resource").isNotNull();
            String ddl = new String(is.readAllBytes(), StandardCharsets.UTF_8).replaceAll("(?m)^--.*$", "");
            for (String command : ddl.split(";")) {
                if (!command.isBlank()) {
                    stmt.execute(command.trim());
                }
            }
        }

        tx = new TransactionalExecutor() {
            @Override
            public void execute(TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public void executeManaged(TransactionalWork work) {
                try {
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    conn.beginTransaction();
                    work.run(conn);
                    conn.commit();
                } catch (Exception e) {
                    try {
                        jdbcConn.rollback();
                    } catch (SQLException ignored) {
                        // the original failure is the one to report
                    }
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public <T> T query(Function<PersistenceConnection, T> query) {
                try {
                    return query.apply(new JdbcPersistenceConnection(jdbcConn));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        flowStateRepo = flowRepo(KEY_RING_A);
        identityRepo = new PostgresExternalIdentityRepository(tx);
    }

    @AfterAll
    static void tearDownDatabase() throws SQLException {
        if (jdbcConn != null) {
            jdbcConn.close();
        }
    }

    @Test
    @DisplayName("a second repository holding the same keyring consumes a state the first saved; another keyring leaves it in place")
    void sharedKeyringAcrossNodes() {
        Instant now = Instant.now();
        FlowStateRecord record = new FlowStateRecord("pg-state-shared", "google", "https://app.exeris.eu/cb", null,
                "verifier-shared", "n", now, now.plusSeconds(300), "binding-hash");
        flowRepo(KEY_RING_A).save(record);

        // a node with a different keyring cannot open it, and the failed attempt must not consume it
        assertThatThrownBy(() -> flowRepo(KEY_RING_OTHER).consume("pg-state-shared", now))
                .isInstanceOf(FlowStateUnreadableException.class);
        assertThatThrownBy(() -> flowRepo(KEY_RING_OTHER).consume("pg-state-shared", now))
                .isInstanceOf(FlowStateUnreadableException.class);

        // another node that holds the key (a "restarted" instance) still completes it, exactly once
        Optional<FlowStateRecord> consumed = flowRepo(KEY_RING_A).consume("pg-state-shared", now);
        assertThat(consumed).isPresent();
        assertThat(consumed.get().codeVerifier()).isEqualTo("verifier-shared");
        assertThat(consumed.get().bindingHash()).isEqualTo("binding-hash");
        assertThat(flowRepo(KEY_RING_A).consume("pg-state-shared", now)).isEmpty();
    }

    @Test
    @DisplayName("a verifier sealed for one state row does not open on another row")
    void sealedVerifierIsBoundToItsRow() throws SQLException {
        Instant now = Instant.now();
        flowStateRepo.save(new FlowStateRecord("pg-state-src", "google", "https://app.exeris.eu/cb", null,
                "verifier-src", null, now, now.plusSeconds(300), "b"));
        flowStateRepo.save(new FlowStateRecord("pg-state-dst", "google", "https://app.exeris.eu/cb", null,
                "verifier-dst", null, now, now.plusSeconds(300), "b"));
        try (Statement stmt = jdbcConn.createStatement()) {
            stmt.execute("UPDATE federated_flow_states SET encrypted_code_verifier = "
                    + "(SELECT encrypted_code_verifier FROM federated_flow_states WHERE state_hash = 'pg-state-src') "
                    + "WHERE state_hash = 'pg-state-dst'");
        }

        assertThatThrownBy(() -> flowStateRepo.consume("pg-state-dst", now)).isInstanceOf(FlowStateUnreadableException.class);
        assertThat(flowStateRepo.consume("pg-state-src", now)).isPresent();
    }

    @Test
    @DisplayName("flow state save, encrypted verifier round-trip, atomic consumption, and replay rejection")
    void flowStateLifecyclePostgres() {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300);

        FlowStateRecord record = new FlowStateRecord(
                "pg-state-hash-1",
                "google",
                "https://app.exeris.eu/cb",
                "https://app.exeris.eu/dash",
                "secret-pkce-verifier-12345",
                "nonce-val-999",
                now,
                expiresAt,
                "binding-hash"
        );

        flowStateRepo.save(record);

        // First consume succeeds and verifier is decrypted
        Optional<FlowStateRecord> consumed = flowStateRepo.consume("pg-state-hash-1", now);
        assertThat(consumed).isPresent();
        assertThat(consumed.get().providerId()).isEqualTo("google");
        assertThat(consumed.get().codeVerifier()).isEqualTo("secret-pkce-verifier-12345");
        assertThat(consumed.get().nonce()).isEqualTo("nonce-val-999");
        assertThat(consumed.get().targetPostLoginUrl()).isEqualTo("https://app.exeris.eu/dash");

        // Second consume fails (single-use delete-on-read)
        Optional<FlowStateRecord> replayed = flowStateRepo.consume("pg-state-hash-1", now);
        assertThat(replayed).isEmpty();
    }

    @Test
    @DisplayName("flow state without PKCE verifier round-trips correctly on PostgreSQL")
    void nonPkceFlowStatePostgres() {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300);

        FlowStateRecord record = new FlowStateRecord(
                "pg-state-no-pkce",
                "custom-provider",
                "https://app.exeris.eu/cb",
                null,
                null,
                null,
                now,
                expiresAt,
                "binding-hash"
        );

        flowStateRepo.save(record);

        Optional<FlowStateRecord> consumed = flowStateRepo.consume("pg-state-no-pkce", now);
        assertThat(consumed).isPresent();
        assertThat(consumed.get().codeVerifier()).isNull();
        assertThat(consumed.get().nonce()).isNull();
        assertThat(consumed.get().targetPostLoginUrl()).isNull();
    }

    @Test
    @DisplayName("external identity linking, lookup, conflict rejection, and unlink on PostgreSQL")
    void identityLinkLifecyclePostgres() {
        UUID linkId = UUID.randomUUID();
        UUID localSubject = UUID.randomUUID();
        String issuer = "https://accounts.google.com";
        String externalSubject = "g-user-8888";
        Instant now = Instant.now();

        // 1. Save link
        identityRepo.saveLink(
                linkId,
                localSubject,
                issuer,
                externalSubject,
                "user8888@gmail.com",
                true,
                Map.of("role", "developer"),
                now
        );

        // 2. Find linked subject
        Optional<UUID> foundSubject = identityRepo.findLinkedSubject(issuer, externalSubject);
        assertThat(foundSubject).contains(localSubject);

        // 3. Find link record
        Optional<ExternalLinkRecord> foundLink = identityRepo.findLink(localSubject, issuer);
        assertThat(foundLink).isPresent();
        assertThat(foundLink.get().id()).isEqualTo(linkId);
        assertThat(foundLink.get().email()).isEqualTo("user8888@gmail.com");
        assertThat(foundLink.get().emailVerified()).isTrue();
        assertThat(foundLink.get().metadata()).containsEntry("role", "developer");

        // 4. Conflict detection: link same external subject to another local subject
        UUID anotherSubject = UUID.randomUUID();
        assertThatThrownBy(() -> identityRepo.saveLink(
                UUID.randomUUID(),
                anotherSubject,
                issuer,
                externalSubject,
                "other@gmail.com",
                true,
                Map.of(),
                now
        )).isInstanceOf(IdentityLinkConflictException.class);

        // 5. Conflict detection: link same local subject to another external subject on same issuer
        assertThatThrownBy(() -> identityRepo.saveLink(
                UUID.randomUUID(),
                localSubject,
                issuer,
                "g-user-different",
                "other@gmail.com",
                true,
                Map.of(),
                now
        )).isInstanceOf(IdentityLinkConflictException.class);

        // 6. List links
        List<ExternalLinkRecord> list = identityRepo.listLinks(localSubject);
        assertThat(list).hasSize(1);
        assertThat(list.get(0).externalSubject()).isEqualTo(externalSubject);

        // 7. Delete link
        boolean deleted = identityRepo.deleteLink(localSubject, issuer);
        assertThat(deleted).isTrue();
        assertThat(identityRepo.findLinkedSubject(issuer, externalSubject)).isEmpty();
    }

    @Test
    @DisplayName("re-linking same external identity in PostgreSQL updates fields while preserving id and linkedAt")
    void updateExistingLinkPostgres() {
        UUID initialId = UUID.randomUUID();
        UUID localSubject = UUID.randomUUID();
        String issuer = "https://accounts.google.com";
        String externalSubject = "g-user-update-pg";
        Instant initialLinkedAt = Instant.now().minusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        ExternalLinkRecord initial = identityRepo.saveLink(
                initialId,
                localSubject,
                issuer,
                externalSubject,
                "initial@gmail.com",
                false,
                Map.of("v", 1),
                initialLinkedAt,
                initialLinkedAt
        );

        Instant updateTime = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        ExternalLinkRecord updated = identityRepo.saveLink(
                UUID.randomUUID(), // new ID should be ignored in favor of existing link ID
                localSubject,
                issuer,
                externalSubject,
                "updated@gmail.com",
                true,
                Map.of("v", 2, "premium", true),
                initialLinkedAt,
                updateTime
        );

        assertThat(updated.id()).isEqualTo(initial.id());
        assertThat(updated.linkedAt()).isEqualTo(initial.linkedAt());
        assertThat(updated.email()).isEqualTo("updated@gmail.com");
        assertThat(updated.emailVerified()).isTrue();
        assertThat(updated.metadata()).containsEntry("v", 2).containsEntry("premium", true);

        Optional<ExternalLinkRecord> fetched = identityRepo.findLink(localSubject, issuer);
        assertThat(fetched).isPresent();
        assertThat(fetched.get().id()).isEqualTo(initial.id());
        assertThat(fetched.get().email()).isEqualTo("updated@gmail.com");
        assertThat(fetched.get().emailVerified()).isTrue();
    }

    @Test
    @DisplayName("expired flow state in PostgreSQL is rejected on consume and atomically deleted")
    void expiredFlowStateConsumedAndDeletedPostgres() {
        Instant now = Instant.now();
        Instant expiredTime = now.minusSeconds(10);

        FlowStateRecord record = new FlowStateRecord(
                "pg-state-expired",
                "google",
                "https://app.exeris.eu/cb",
                null,
                "verifier-to-delete",
                null,
                now.minusSeconds(300),
                expiredTime,
                "binding-hash"
        );

        flowStateRepo.save(record);

        // Consume of expired flow state returns empty
        Optional<FlowStateRecord> consumed = flowStateRepo.consume("pg-state-expired", now);
        assertThat(consumed).isEmpty();

        // And verifies it was atomically deleted from Postgres (second consume still empty)
        Optional<FlowStateRecord> secondConsume = flowStateRepo.consume("pg-state-expired", now);
        assertThat(secondConsume).isEmpty();
    }
}
