package eu.exeris.caps.federatedlogin.internal.repository;

import java.time.Instant;
import java.util.Optional;

/**
 * Storage contract for ephemeral federated flow states with atomic single-use consumption.
 *
 * @since 0.1.0
 */
public interface FlowStateRepository {

    /**
     * Persists an initiated authorization flow state.
     *
     * @param record flow state record; must not be {@code null}
     */
    void save(FlowStateRecord record);

    /**
     * Atomically retrieves and removes (consumes) the flow state record for the given state hash,
     * verifying that it has not expired.
     *
     * <p>Subsequent calls with the same state hash must return {@link Optional#empty()} to guarantee
     * single-use semantics and replay attack prevention.
     *
     * @param stateHash SHA-256 hash of the flow state
     * @param now       current evaluation instant
     * @return consumed flow state record if present and not expired, empty otherwise
     */
    Optional<FlowStateRecord> consume(String stateHash, Instant now);

    /**
     * Prunes expired flow states older than {@code now}.
     *
     * @param now current evaluation instant
     */
    void pruneExpired(Instant now);
}
