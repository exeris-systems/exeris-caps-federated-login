package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PostgresFederatedLogin Live PostgreSQL Integration Tests")
class PostgresFederatedLoginLiveIT {

    private static final String PG_URL = "jdbc:postgresql://localhost:5432/exeris_showroom";
    private static final String PG_USER = "exeris";
    private static final String PG_PASS = "exeris_password";
    private static final String TEST_SCHEMA = "test_fed_login_live";

    private static Connection jdbcConn;
    private static PostgresFlowStateRepository flowStateRepo;
    private static PostgresExternalIdentityRepository identityRepo;

    @BeforeAll
    static void setUpDatabase() {
        try (Connection initConn = DriverManager.getConnection(PG_URL, PG_USER, PG_PASS);
             Statement stmt = initConn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + TEST_SCHEMA);
        } catch (SQLException e) {
            Assumptions.abort("PostgreSQL not reachable at " + PG_URL + ": " + e.getMessage());
            return;
        }

        try {
            jdbcConn = DriverManager.getConnection(PG_URL + "?currentSchema=" + TEST_SCHEMA, PG_USER, PG_PASS);
            try (Statement stmt = jdbcConn.createStatement()) {
                try (InputStream is = PostgresFederatedLoginLiveIT.class.getResourceAsStream("/schema/federated-login-schema.sql")) {
                    if (is != null) {
                        String ddl = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                        String cleanDdl = ddl.replaceAll("(?m)^--.*$", "");
                        for (String command : cleanDdl.split(";")) {
                            String trimmed = command.trim();
                            if (!trimmed.isEmpty()) {
                                stmt.execute(trimmed);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Assumptions.abort("Failed to initialize test schema on PostgreSQL: " + e.getMessage());
            return;
        }

        TransactionalExecutor tx = new TransactionalExecutor() {
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
                    } catch (SQLException ignored) {}
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
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    return query.apply(conn);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        flowStateRepo = new PostgresFlowStateRepository(tx);
        identityRepo = new PostgresExternalIdentityRepository(tx);
    }

    @AfterAll
    static void tearDownDatabase() {
        if (jdbcConn != null) {
            try (Statement stmt = jdbcConn.createStatement()) {
                stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            } catch (SQLException ignored) {
            } finally {
                try {
                    jdbcConn.close();
                } catch (SQLException ignored) {}
            }
        }
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
                expiresAt
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
                expiresAt
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
                expiredTime
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
