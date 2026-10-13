package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.internal.crypto.FlowStateCrypto;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * PostgreSQL implementation of {@link FlowStateRepository} utilizing {@link TransactionalExecutor}.
 *
 * <p>Encrypts code verifiers at rest with AES-256-GCM and uses atomic {@code DELETE ... RETURNING}
 * queries to guarantee strict single-use consumption and double-spend protection.
 *
 * @since 0.1.0
 */
public final class PostgresFlowStateRepository implements FlowStateRepository {

    private final TransactionalExecutor tx;
    private final FlowStateCrypto crypto;

    public PostgresFlowStateRepository(TransactionalExecutor tx) {
        this(tx, new FlowStateCrypto());
    }

    public PostgresFlowStateRepository(TransactionalExecutor tx, FlowStateCrypto crypto) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
        this.crypto = Objects.requireNonNull(crypto, "crypto must not be null");
    }

    @Override
    public void save(FlowStateRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        String encryptedVerifier = crypto.encrypt(record.codeVerifier());

        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO federated_flow_states " +
                    "(state_hash, provider_id, redirect_uri, target_post_login_url, encrypted_code_verifier, nonce, created_at, expires_at) " +
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) " +
                    "ON CONFLICT (state_hash) DO UPDATE SET " +
                    "provider_id = EXCLUDED.provider_id, " +
                    "redirect_uri = EXCLUDED.redirect_uri, " +
                    "target_post_login_url = EXCLUDED.target_post_login_url, " +
                    "encrypted_code_verifier = EXCLUDED.encrypted_code_verifier, " +
                    "nonce = EXCLUDED.nonce, " +
                    "created_at = EXCLUDED.created_at, " +
                    "expires_at = EXCLUDED.expires_at")) {
                stmt.bindString(0, record.stateHash())
                    .bindString(1, record.providerId())
                    .bindString(2, record.redirectUri());

                if (record.targetPostLoginUrl() != null) {
                    stmt.bindString(3, record.targetPostLoginUrl());
                } else {
                    stmt.bindNull(3);
                }

                stmt.bindString(4, encryptedVerifier != null ? encryptedVerifier : "");

                if (record.nonce() != null) {
                    stmt.bindString(5, record.nonce());
                } else {
                    stmt.bindNull(5);
                }

                stmt.bindInstant(6, record.createdAt())
                    .bindInstant(7, record.expiresAt());

                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<FlowStateRecord> consume(String stateHash, Instant now) {
        if (stateHash == null) {
            return Optional.empty();
        }
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "DELETE FROM federated_flow_states " +
                    "WHERE state_hash = $1 " +
                    "RETURNING state_hash, provider_id, redirect_uri, target_post_login_url, encrypted_code_verifier, nonce, created_at, expires_at")) {
                stmt.bindString(0, stateHash);

                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        String hash = row.getString(0);
                        String providerId = row.getString(1);
                        String redirectUri = row.getString(2);
                        String targetUrl = row.isNull(3) ? null : row.getString(3);
                        String encryptedVerifier = row.getString(4);
                        String nonce = row.isNull(5) ? null : row.getString(5);
                        Instant createdAt = row.getInstant(6);
                        Instant expiresAt = row.getInstant(7);

                        if (!now.isBefore(expiresAt)) {
                            return Optional.empty();
                        }

                        String decryptedVerifier = (encryptedVerifier != null && !encryptedVerifier.isBlank())
                                ? crypto.decrypt(encryptedVerifier)
                                : null;

                        return Optional.of(new FlowStateRecord(
                                hash,
                                providerId,
                                redirectUri,
                                targetUrl,
                                decryptedVerifier,
                                nonce,
                                createdAt,
                                expiresAt
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public void pruneExpired(Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "DELETE FROM federated_flow_states WHERE expires_at <= $1")) {
                stmt.bindInstant(0, now);
                stmt.executeUpdate();
            }
        });
    }
}
