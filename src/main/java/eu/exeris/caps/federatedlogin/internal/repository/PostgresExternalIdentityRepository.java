package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;
import eu.exeris.caps.federatedlogin.internal.http.JsonReader;
import eu.exeris.kernel.spi.exceptions.persistence.PersistenceProviderException;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * PostgreSQL implementation of {@link ExternalIdentityRepository} using {@link TransactionalExecutor}.
 *
 * @since 0.1.0
 */
public final class PostgresExternalIdentityRepository implements ExternalIdentityRepository {

    private final TransactionalExecutor tx;

    public PostgresExternalIdentityRepository(TransactionalExecutor tx) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
    }

    @Override
    public Optional<UUID> findLinkedSubject(String issuer, String externalSubject) {
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");

        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT local_subject_id FROM external_identity_links " +
                    "WHERE issuer = $1 AND external_subject = $2")) {
                stmt.bindString(0, issuer)
                    .bindString(1, externalSubject);

                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(rs.row().getUuid(0));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public Optional<ExternalLinkRecord> findLink(UUID localSubjectId, String issuer) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");

        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, local_subject_id, issuer, external_subject, email, email_verified, metadata, linked_at, updated_at " +
                    "FROM external_identity_links " +
                    "WHERE local_subject_id = $1 AND issuer = $2")) {
                stmt.bindUuid(0, localSubjectId)
                    .bindString(1, issuer);

                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapRow(rs.row()));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public ExternalLinkRecord saveLink(
            UUID id,
            UUID localSubjectId,
            String issuer,
            String externalSubject,
            String email,
            boolean emailVerified,
            Map<String, Object> metadata,
            Instant linkedAt,
            Instant updatedAt
    ) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");
        Objects.requireNonNull(linkedAt, "linkedAt must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");

        // Pre-check constraints
        Optional<UUID> existingLinked = findLinkedSubject(issuer, externalSubject);
        if (existingLinked.isPresent() && !existingLinked.get().equals(localSubjectId)) {
            throw new IdentityLinkConflictException(
                    "External identity (" + issuer + ", " + externalSubject + ") is already linked to subject " + existingLinked.get());
        }

        Optional<ExternalLinkRecord> existingLink = findLink(localSubjectId, issuer);
        if (existingLink.isPresent() && !existingLink.get().externalSubject().equals(externalSubject)) {
            throw new IdentityLinkConflictException(
                    "Local subject " + localSubjectId + " already has a linked identity for issuer " + issuer);
        }

        UUID targetId = existingLink.map(ExternalLinkRecord::id).orElse(id);
        Instant effectiveLinkedAt = existingLink.map(ExternalLinkRecord::linkedAt).orElse(linkedAt);
        String metadataJson = (metadata != null && !metadata.isEmpty()) ? JsonReader.toJson(metadata) : null;

        try {
            tx.executeManaged(conn -> {
                try (PersistenceStatement stmt = conn.prepare(
                        "INSERT INTO external_identity_links " +
                        "(id, local_subject_id, issuer, external_subject, email, email_verified, metadata, linked_at, updated_at) " +
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) " +
                        "ON CONFLICT (local_subject_id, issuer) DO UPDATE SET " +
                        "email = EXCLUDED.email, " +
                        "email_verified = EXCLUDED.email_verified, " +
                        "metadata = EXCLUDED.metadata, " +
                        "updated_at = EXCLUDED.updated_at")) {
                    stmt.bindUuid(0, targetId)
                        .bindUuid(1, localSubjectId)
                        .bindString(2, issuer)
                        .bindString(3, externalSubject);

                    if (email != null) {
                        stmt.bindString(4, email);
                    } else {
                        stmt.bindNull(4);
                    }

                    stmt.bindBoolean(5, emailVerified);

                    if (metadataJson != null) {
                        stmt.bindString(6, metadataJson);
                    } else {
                        stmt.bindNull(6);
                    }

                    stmt.bindInstant(7, effectiveLinkedAt)
                        .bindInstant(8, updatedAt);

                    stmt.executeUpdate();
                }
            });
        } catch (PersistenceProviderException ppe) {
            String sqlState = (ppe.rawArgs() != null && ppe.rawArgs().length > 0 && ppe.rawArgs()[0] != null)
                    ? ppe.rawArgs()[0].toString()
                    : "";
            if ("23505".equals(sqlState) || ppe.getMessage().contains("23505") || ppe.getMessage().contains("duplicate key")) {
                throw new IdentityLinkConflictException("Identity link conflict violating uniqueness constraint", ppe);
            }
            throw ppe;
        } catch (RuntimeException re) {
            if (re.getMessage() != null && (re.getMessage().contains("23505") || re.getMessage().contains("duplicate key"))) {
                throw new IdentityLinkConflictException("Identity link conflict violating uniqueness constraint", re);
            }
            throw re;
        }

        return new ExternalLinkRecord(
                targetId,
                localSubjectId,
                issuer,
                externalSubject,
                email,
                emailVerified,
                metadata,
                effectiveLinkedAt,
                updatedAt
        );
    }

    @Override
    public boolean deleteLink(UUID localSubjectId, String issuer) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");

        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "DELETE FROM external_identity_links WHERE local_subject_id = $1 AND issuer = $2")) {
                stmt.bindUuid(0, localSubjectId)
                    .bindString(1, issuer);
                return stmt.executeUpdate() > 0;
            }
        });
    }

    @Override
    public List<ExternalLinkRecord> listLinks(UUID localSubjectId) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");

        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, local_subject_id, issuer, external_subject, email, email_verified, metadata, linked_at, updated_at " +
                    "FROM external_identity_links WHERE local_subject_id = $1 ORDER BY linked_at ASC")) {
                stmt.bindUuid(0, localSubjectId);

                try (QueryResult rs = stmt.executeQuery()) {
                    List<ExternalLinkRecord> list = new ArrayList<>();
                    while (rs.next()) {
                        list.add(mapRow(rs.row()));
                    }
                    return list;
                }
            }
        });
    }

    private ExternalLinkRecord mapRow(RowCursor row) {
        UUID id = row.getUuid(0);
        UUID localSubjectId = row.getUuid(1);
        String issuer = row.getString(2);
        String externalSubject = row.getString(3);
        String email = row.isNull(4) ? null : row.getString(4);
        boolean emailVerified = row.getBoolean(5);
        String metadataStr = row.isNull(6) ? null : row.getString(6);
        Instant linkedAt = row.getInstant(7);
        Instant updatedAt = row.getInstant(8);

        Map<String, Object> metadata = (metadataStr != null && !metadataStr.isBlank())
                ? JsonReader.parseObject(metadataStr)
                : Map.of();

        return new ExternalLinkRecord(
                id,
                localSubjectId,
                issuer,
                externalSubject,
                email,
                emailVerified,
                metadata,
                linkedAt,
                updatedAt
        );
    }
}
