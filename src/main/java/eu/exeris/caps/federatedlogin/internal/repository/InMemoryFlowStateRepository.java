package eu.exeris.caps.federatedlogin.internal.repository;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory test double and standalone implementation of {@link FlowStateRepository}.
 *
 * @since 0.1.0
 */
public final class InMemoryFlowStateRepository implements FlowStateRepository {

    private final Map<String, FlowStateRecord> store = new ConcurrentHashMap<>();

    @Override
    public void save(FlowStateRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        store.put(record.stateHash(), record);
    }

    @Override
    public Optional<FlowStateRecord> consume(String stateHash, Instant now) {
        if (stateHash == null) {
            return Optional.empty();
        }
        FlowStateRecord removed = store.remove(stateHash);
        if (removed == null) {
            return Optional.empty();
        }
        if (removed.isExpired(now)) {
            return Optional.empty();
        }
        return Optional.of(removed);
    }

    @Override
    public void pruneExpired(Instant now) {
        store.values().removeIf(record -> record.isExpired(now));
    }
}
