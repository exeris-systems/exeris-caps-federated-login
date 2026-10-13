package eu.exeris.caps.federatedlogin.api.model;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Persistent binding between a local subject and an external provider identity.
 *
 * @param id              unique link record identifier
 * @param localSubjectId  local user/subject identifier
 * @param issuer          issuer URI of the provider
 * @param externalSubject subject identifier from the provider
 * @param email           associated email address at the provider
 * @param emailVerified   whether email is verified at provider
 * @param metadata        arbitrary profile metadata (e.g. privacy masking flags)
 * @param linkedAt        timestamp when link was established
 * @param updatedAt       timestamp when link record was last updated
 * @since 0.1.0
 */
public record ExternalLinkRecord(
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
    public ExternalLinkRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(localSubjectId, "localSubjectId must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(externalSubject, "externalSubject must not be null");
        Objects.requireNonNull(linkedAt, "linkedAt must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");
        if (metadata != null) {
            metadata = Collections.unmodifiableMap(new LinkedHashMap<>(metadata));
        } else {
            metadata = Map.of();
        }
    }
}
