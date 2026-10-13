package eu.exeris.caps.federatedlogin.api;

import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Service managing bindings between local subject accounts and external provider identities.
 *
 * <p>Enforces strict single-binding rules per issuer and subject to prevent identity confusion:
 * <ul>
 *   <li>An external identity {@code (issuer, externalSubject)} can be bound to at most one local subject.</li>
 *   <li>A local subject can have at most one external identity bound for a given {@code issuer}.</li>
 * </ul>
 *
 * @since 0.1.0
 */
public interface ExternalIdentityLink {

    /**
     * Looks up the local subject ID linked to an external provider subject.
     *
     * @param issuer          canonical provider issuer URI (e.g. "https://accounts.google.com")
     * @param externalSubject external subject ID
     * @return linked local subject ID if an active link exists
     */
    Optional<UUID> findLinkedSubject(String issuer, String externalSubject);

    /**
     * Finds the link record for a given local subject and provider issuer.
     *
     * @param localSubjectId local user/subject identifier
     * @param issuer         provider issuer URI
     * @return link record if found
     */
    Optional<ExternalLinkRecord> findLink(UUID localSubjectId, String issuer);

    /**
     * Establishes a binding between a local subject and an external provider identity.
     *
     * @param localSubjectId  local user/subject identifier
     * @param issuer          provider issuer URI
     * @param externalSubject external subject ID
     * @param email           associated email address
     * @param emailVerified   whether email is verified by the provider
     * @param metadata        arbitrary profile metadata
     * @return the created link record
     * @throws IdentityLinkConflictException if the external identity is already linked to another local subject,
     *                                       or if the local subject is already linked to another identity for this issuer
     */
    ExternalLinkRecord link(
            UUID localSubjectId,
            String issuer,
            String externalSubject,
            String email,
            boolean emailVerified,
            Map<String, Object> metadata
    );

    /**
     * Removes the identity link for a given local subject and provider issuer.
     *
     * @param localSubjectId local user/subject identifier
     * @param issuer         provider issuer URI
     * @return true if a link existed and was removed, false otherwise
     */
    boolean unlink(UUID localSubjectId, String issuer);

    /**
     * Lists all external identity links bound to a local subject.
     *
     * @param localSubjectId local user/subject identifier
     * @return list of link records
     */
    List<ExternalLinkRecord> listLinks(UUID localSubjectId);
}
