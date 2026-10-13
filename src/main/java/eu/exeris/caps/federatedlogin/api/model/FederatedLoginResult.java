package eu.exeris.caps.federatedlogin.api.model;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Result of processing a federated authentication callback.
 *
 * <p>In accordance with pre-account takeover protection rules (ADR-099), external identities are
 * never automatically linked to local accounts by email alone. If an active link exists for
 * {@code (issuer, externalSubject)}, {@link #linkedLocalSubjectId()} contains the local subject ID
 * and {@link #isNewLink()} is {@code false}. If no link exists, {@link #linkedLocalSubjectId()} is
 * empty and {@link #isNewLink()} is {@code true}, leaving link admission and verification to the
 * higher-tier SKU orchestration layer.
 *
 * @param linkedLocalSubjectId optional local subject identifier bound to the external identity
 * @param identity             standardized external identity attributes
 * @param isNewLink            true if no existing link was found for this external identity
 * @param targetPostLoginUrl   original post-login destination URL requested during flow initiation
 * @since 0.1.0
 */
public record FederatedLoginResult(
        Optional<UUID> linkedLocalSubjectId,
        FederatedIdentity identity,
        boolean isNewLink,
        String targetPostLoginUrl
) {
    public FederatedLoginResult {
        Objects.requireNonNull(linkedLocalSubjectId, "linkedLocalSubjectId must not be null");
        Objects.requireNonNull(identity, "identity must not be null");
    }

    public static FederatedLoginResult linked(UUID localSubjectId, FederatedIdentity identity, String targetPostLoginUrl) {
        return new FederatedLoginResult(Optional.of(Objects.requireNonNull(localSubjectId, "localSubjectId")), identity, false, targetPostLoginUrl);
    }

    public static FederatedLoginResult unlinked(FederatedIdentity identity, String targetPostLoginUrl) {
        return new FederatedLoginResult(Optional.empty(), identity, true, targetPostLoginUrl);
    }
}
