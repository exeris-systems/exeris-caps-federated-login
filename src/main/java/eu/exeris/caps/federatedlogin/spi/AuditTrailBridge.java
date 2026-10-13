package eu.exeris.caps.federatedlogin.spi;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Bridge for emitting security and compliance audit events to {@link AuditLogSink} when present.
 *
 * @since 0.1.0
 */
public final class AuditTrailBridge {

    private final AuditLogSink sink;

    public AuditTrailBridge(AuditLogSink sink) {
        this.sink = sink;
    }

    /**
     * Emits an audit event if the underlying sink is configured.
     *
     * @param action    the audit action name
     * @param actorId   actor identifier (e.g. subject ID or "system")
     * @param details   key-value metadata
     */
    public void emit(String action, String actorId, Map<String, Object> details) {
        if (sink != null) {
            sink.emit(AuditEvent.builder()
                    .action(action)
                    .resourceType("federated-identity")
                    .resourceId(details != null && details.containsKey("external_subject") ? String.valueOf(details.get("external_subject")) : "")
                    .actorId(actorId != null ? actorId : "system")
                    .timestamp(Instant.now())
                    .details(details)
                    .build());
        }
    }

    /**
     * Convenience method when subject is a UUID.
     */
    public void emit(String action, UUID subjectId, Map<String, Object> details) {
        emit(action, subjectId != null ? subjectId.toString() : "system", details);
    }
}
