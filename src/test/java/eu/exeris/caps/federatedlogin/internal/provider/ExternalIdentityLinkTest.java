package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.federatedlogin.api.exception.IdentityLinkConflictException;
import eu.exeris.caps.federatedlogin.api.model.ExternalLinkRecord;
import eu.exeris.caps.federatedlogin.internal.repository.InMemoryExternalIdentityRepository;
import eu.exeris.caps.federatedlogin.spi.AuditTrailBridge;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ExternalIdentityLink Unit Tests")
class ExternalIdentityLinkTest {

    private static final class TestAuditSink implements AuditLogSink {
        final List<AuditEvent> events = new ArrayList<>();

        @Override
        public void emit(AuditEvent event) {
            events.add(event);
        }

        @Override
        public List<AuditEvent> query(eu.exeris.caps.audittrail.api.AuditQuery query) {
            return List.of();
        }

        @Override
        public long count(eu.exeris.caps.audittrail.api.AuditQuery query) {
            return events.size();
        }
    }

    @Test
    @DisplayName("link, find, list, and unlink lifecycle")
    void linkLifecycle() {
        TestAuditSink sink = new TestAuditSink();
        AuditTrailBridge auditTrail = new AuditTrailBridge(sink);
        DefaultExternalIdentityLink service = new DefaultExternalIdentityLink(
                new InMemoryExternalIdentityRepository(),
                auditTrail
        );

        UUID subjectId = UUID.randomUUID();
        String issuer = "https://accounts.google.com";
        String externalSubject = "google-sub-123456";

        // 1. Initially unlinked
        assertThat(service.findLinkedSubject(issuer, externalSubject)).isEmpty();
        assertThat(service.findLink(subjectId, issuer)).isEmpty();

        // 2. Establish link
        ExternalLinkRecord record = service.link(
                subjectId,
                issuer,
                externalSubject,
                "user@example.com",
                true,
                Map.of("profile", "google")
        );

        assertThat(record.localSubjectId()).isEqualTo(subjectId);
        assertThat(record.issuer()).isEqualTo(issuer);
        assertThat(record.externalSubject()).isEqualTo(externalSubject);
        assertThat(record.email()).isEqualTo("user@example.com");
        assertThat(record.emailVerified()).isTrue();
        assertThat(record.metadata()).containsEntry("profile", "google");

        // 3. Find operations succeed
        Optional<UUID> foundSubject = service.findLinkedSubject(issuer, externalSubject);
        assertThat(foundSubject).contains(subjectId);

        Optional<ExternalLinkRecord> foundRecord = service.findLink(subjectId, issuer);
        assertThat(foundRecord).isPresent();
        assertThat(foundRecord.get().id()).isEqualTo(record.id());

        // 4. List links
        List<ExternalLinkRecord> links = service.listLinks(subjectId);
        assertThat(links).hasSize(1);
        assertThat(links.get(0).externalSubject()).isEqualTo(externalSubject);

        // 5. Unlink
        boolean unlinked = service.unlink(subjectId, issuer);
        assertThat(unlinked).isTrue();
        assertThat(service.findLinkedSubject(issuer, externalSubject)).isEmpty();
        assertThat(service.findLink(subjectId, issuer)).isEmpty();
        assertThat(service.listLinks(subjectId)).isEmpty();

        // 6. Audit events verified
        assertThat(sink.events).hasSize(2);
        assertThat(sink.events.get(0).action()).isEqualTo("FEDERATED_IDENTITY_LINKED");
        assertThat(sink.events.get(1).action()).isEqualTo("FEDERATED_IDENTITY_UNLINKED");
    }

    @Test
    @DisplayName("conflict detection when same external identity is linked to another subject")
    void duplicateExternalIdentityConflict() {
        DefaultExternalIdentityLink service = new DefaultExternalIdentityLink(
                new InMemoryExternalIdentityRepository(),
                null
        );

        UUID subject1 = UUID.randomUUID();
        UUID subject2 = UUID.randomUUID();
        String issuer = "https://github.com";
        String externalSubject = "octocat-999";

        service.link(subject1, issuer, externalSubject, "user1@github.com", true, Map.of());

        assertThatThrownBy(() -> service.link(subject2, issuer, externalSubject, "user2@github.com", true, Map.of()))
                .isInstanceOf(IdentityLinkConflictException.class)
                .hasMessageContaining("already linked");
    }

    @Test
    @DisplayName("conflict detection when same local subject already has a link for the issuer")
    void duplicateSubjectIssuerConflict() {
        DefaultExternalIdentityLink service = new DefaultExternalIdentityLink(
                new InMemoryExternalIdentityRepository(),
                null
        );

        UUID subject = UUID.randomUUID();
        String issuer = "https://github.com";

        service.link(subject, issuer, "sub-1", "user@github.com", true, Map.of());

        assertThatThrownBy(() -> service.link(subject, issuer, "sub-2", "user@github.com", true, Map.of()))
                .isInstanceOf(IdentityLinkConflictException.class)
                .hasMessageContaining("already has a linked identity");
    }

    @Test
    @DisplayName("re-linking same external identity updates email/metadata while preserving id and linkedAt")
    void updateExistingLinkPreservesIdAndLinkedAt() {
        DefaultExternalIdentityLink service = new DefaultExternalIdentityLink(
                new InMemoryExternalIdentityRepository(),
                null
        );

        UUID subject = UUID.randomUUID();
        String issuer = "https://accounts.google.com";
        String externalSubject = "g-user-42";

        ExternalLinkRecord firstRecord = service.link(
                subject,
                issuer,
                externalSubject,
                "old@gmail.com",
                false,
                Map.of("v", 1)
        );

        ExternalLinkRecord updatedRecord = service.link(
                subject,
                issuer,
                externalSubject,
                "new@gmail.com",
                true,
                Map.of("v", 2, "role", "admin")
        );

        assertThat(updatedRecord.id()).isEqualTo(firstRecord.id());
        assertThat(updatedRecord.linkedAt()).isEqualTo(firstRecord.linkedAt());
        assertThat(updatedRecord.email()).isEqualTo("new@gmail.com");
        assertThat(updatedRecord.emailVerified()).isTrue();
        assertThat(updatedRecord.metadata()).containsEntry("v", 2).containsEntry("role", "admin");

        List<ExternalLinkRecord> links = service.listLinks(subject);
        assertThat(links).hasSize(1);
        assertThat(links.get(0).id()).isEqualTo(firstRecord.id());
        assertThat(links.get(0).email()).isEqualTo("new@gmail.com");
    }

    @Test
    @DisplayName("null input validation on ExternalIdentityLink methods")
    void nullInputValidation() {
        DefaultExternalIdentityLink service = new DefaultExternalIdentityLink(
                new InMemoryExternalIdentityRepository(),
                null
        );

        assertThatThrownBy(() -> service.link(null, "iss", "sub", "mail", true, Map.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> service.link(UUID.randomUUID(), null, "sub", "mail", true, Map.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> service.link(UUID.randomUUID(), "iss", null, "mail", true, Map.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> service.unlink(null, "iss"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> service.unlink(UUID.randomUUID(), null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> service.listLinks(null))
                .isInstanceOf(NullPointerException.class);
    }
}
