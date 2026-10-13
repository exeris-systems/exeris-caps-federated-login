package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.ExternalIdentityLink;
import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;
import eu.exeris.caps.federatedlogin.internal.repository.ExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.spi.AuditTrailBridge;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link ExternalIdentityLink}.
 *
 * @since 0.1.0
 */
public final class DefaultExternalIdentityLink implements ExternalIdentityLink {

    private final ExternalIdentityRepository repository;
    private final AuditTrailBridge auditTrail;

    public DefaultExternalIdentityLink(ExternalIdentityRepository repository, AuditTrailBridge auditTrail) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.auditTrail = auditTrail;
    }

    @Override
    public Optional<UUID> findLinkedSubject(String issuer, String externalSubject) {
        return repository.findLinkedSubject(issuer, externalSubject);
    }

    @Override
    public Optional<ExternalLinkRecord> findLink(UUID localSubjectId, String issuer) {
        return repository.findLink(localSubjectId, issuer);
    }

    @Override
    public ExternalLinkRecord link(
            UUID localSubjectId,
            String issuer,
            String externalSubject,
            String email,
            boolean emailVerified,
            Map<String, Object> metadata
    ) {
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");

        // Pre-check: if subject already linked for this issuer to a different external subject, conflict
        Optional<ExternalLinkRecord> existingLink = repository.findLink(localSubjectId, issuer);
        if (existingLink.isPresent() && !existingLink.get().externalSubject().equals(externalSubject)) {
            throw new IdentityLinkConflictException(
                    "Local subject " + localSubjectId + " already has a linked identity for issuer " + issuer);
        }

        // Pre-check: if external identity already linked to another local subject, conflict
        Optional<UUID> linkedSubject = repository.findLinkedSubject(issuer, externalSubject);
        if (linkedSubject.isPresent() && !linkedSubject.get().equals(localSubjectId)) {
            throw new IdentityLinkConflictException(
                    "External identity (" + issuer + ", " + externalSubject + ") is already linked to subject " + linkedSubject.get());
        }

        UUID id = existingLink.map(ExternalLinkRecord::id).orElseGet(UUID::randomUUID);
        Instant now = Instant.now();
        Instant linkedAt = existingLink.map(ExternalLinkRecord::linkedAt).orElse(now);

        ExternalLinkRecord record = repository.saveLink(
                id,
                localSubjectId,
                issuer,
                externalSubject,
                email,
                emailVerified,
                metadata,
                linkedAt,
                now
        );

        if (auditTrail != null) {
            auditTrail.emit("FEDERATED_IDENTITY_LINKED", localSubjectId, Map.of(
                    "issuer", issuer,
                    "external_subject", externalSubject,
                    "email", email != null ? email : "",
                    "email_verified", emailVerified
            ));
        }

        return record;
    }

    @Override
    public boolean unlink(UUID localSubjectId, String issuer) {
        boolean removed = repository.deleteLink(localSubjectId, issuer);
        if (removed && auditTrail != null) {
            auditTrail.emit("FEDERATED_IDENTITY_UNLINKED", localSubjectId, Map.of(
                    "issuer", issuer
            ));
        }
        return removed;
    }

    @Override
    public List<ExternalLinkRecord> listLinks(UUID localSubjectId) {
        return repository.listLinks(localSubjectId);
    }
}
