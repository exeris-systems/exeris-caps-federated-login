package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory test double and standalone implementation of {@link ExternalIdentityRepository}.
 *
 * @since 0.1.0
 */
public final class InMemoryExternalIdentityRepository implements ExternalIdentityRepository {

    private final Map<UUID, ExternalLinkRecord> recordsById = new ConcurrentHashMap<>();

    @Override
    public Optional<UUID> findLinkedSubject(String issuer, String externalSubject) {
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");

        return recordsById.values().stream()
                .filter(r -> r.issuer().equals(issuer) && r.externalSubject().equals(externalSubject))
                .map(ExternalLinkRecord::localSubjectId)
                .findFirst();
    }

    @Override
    public Optional<ExternalLinkRecord> findLink(UUID localSubjectId, String issuer) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");

        return recordsById.values().stream()
                .filter(r -> r.localSubjectId().equals(localSubjectId) && r.issuer().equals(issuer))
                .findFirst();
    }

    @Override
    public synchronized ExternalLinkRecord saveLink(
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

        // Validate uniqueness constraints
        for (ExternalLinkRecord existing : recordsById.values()) {
            if (!existing.id().equals(id)) {
                if (existing.issuer().equals(issuer) && existing.externalSubject().equals(externalSubject)
                        && !existing.localSubjectId().equals(localSubjectId)) {
                    throw new IdentityLinkConflictException(
                            "External identity (" + issuer + ", " + externalSubject + ") is already linked to subject " + existing.localSubjectId());
                }
                if (existing.localSubjectId().equals(localSubjectId) && existing.issuer().equals(issuer)
                        && !existing.externalSubject().equals(externalSubject)) {
                    throw new IdentityLinkConflictException(
                            "Local subject " + localSubjectId + " already has a linked identity for issuer " + issuer);
                }
            }
        }

        // If a link already exists for this (localSubjectId, issuer), reuse its id and linkedAt
        Optional<ExternalLinkRecord> existingLink = findLink(localSubjectId, issuer);
        UUID recordId = existingLink.map(ExternalLinkRecord::id).orElse(id);
        Instant effectiveLinkedAt = existingLink.map(ExternalLinkRecord::linkedAt).orElse(linkedAt);

        ExternalLinkRecord record = new ExternalLinkRecord(
                recordId,
                localSubjectId,
                issuer,
                externalSubject,
                email,
                emailVerified,
                metadata,
                effectiveLinkedAt,
                updatedAt
        );
        recordsById.put(recordId, record);
        return record;
    }

    @Override
    public synchronized boolean deleteLink(UUID localSubjectId, String issuer) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");

        Optional<ExternalLinkRecord> existing = findLink(localSubjectId, issuer);
        if (existing.isPresent()) {
            recordsById.remove(existing.get().id());
            return true;
        }
        return false;
    }

    @Override
    public List<ExternalLinkRecord> listLinks(UUID localSubjectId) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        List<ExternalLinkRecord> result = new ArrayList<>();
        for (ExternalLinkRecord record : recordsById.values()) {
            if (record.localSubjectId().equals(localSubjectId)) {
                result.add(record);
            }
        }
        return result;
    }
}
