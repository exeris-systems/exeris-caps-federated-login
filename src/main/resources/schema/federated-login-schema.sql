-- Federated Login PostgreSQL Schema (ADR-099, Obligation 9)
-- Layer 5 Domain Primitive: exeris-caps-federated-login

CREATE TABLE IF NOT EXISTS external_identity_links (
    id UUID PRIMARY KEY,
    local_subject_id UUID NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    external_subject VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    metadata TEXT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_external_identity UNIQUE (issuer, external_subject),
    CONSTRAINT uq_local_subject_issuer UNIQUE (local_subject_id, issuer)
);

CREATE INDEX IF NOT EXISTS idx_external_identity_local_subject
    ON external_identity_links (local_subject_id);

CREATE TABLE IF NOT EXISTS federated_flow_states (
    state_hash VARCHAR(64) PRIMARY KEY,
    provider_id VARCHAR(64) NOT NULL,
    redirect_uri VARCHAR(1024) NOT NULL,
    target_post_login_url VARCHAR(1024),
    encrypted_code_verifier TEXT NOT NULL,
    nonce VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_federated_flow_states_expires
    ON federated_flow_states (expires_at);
