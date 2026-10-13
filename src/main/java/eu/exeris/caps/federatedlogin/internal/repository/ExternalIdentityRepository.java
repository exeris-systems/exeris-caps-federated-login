package eu.exeris.caps.federatedlogin.internal.repository;

import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Storage contract for external identity link persistence.
 *
 * @since 0.1.0
 */
public interface ExternalIdentityRepository {

    /**
     * Looks up the local subject ID associated with an issuer and external subject.
     */
    Optional<UUID> findLinkedSubject(String issuer, String externalSubject);

    /**
     * Finds the link record for a given local subject and issuer.
     */
    Optional<ExternalLinkRecord> findLink(UUID localSubjectId, String issuer);

    /**
     * Saves an identity link binding with linkedAt and updatedAt timestamps.
     */
    default ExternalLinkRecord saveLink(
            UUID id,
            UUID localSubjectId,
            String issuer,
            String externalSubject,
            String email,
            boolean emailVerified,
            Map<String, Object> metadata,
            Instant now
    ) {
        return saveLink(id, localSubjectId, issuer, externalSubject, email, emailVerified, metadata, now, now);
    }

    /**
     * Saves or updates an identity link binding preserving original linkedAt timestamp.
     */
    ExternalLinkRecord saveLink(
            UUID id,
            UUID localSubjectId,
            String issuer,
            String externalSubject,
            String email,
            boolean emailVerified,
            Map<String, Object> metadata,
            Instant linkedAt,
            Instant updatedAt
    );

    /**
     * Deletes the link record for the given local subject and issuer.
     */
    boolean deleteLink(UUID localSubjectId, String issuer);

    /**
     * Lists all links for the given local subject.
     */
    List<ExternalLinkRecord> listLinks(UUID localSubjectId);
}
