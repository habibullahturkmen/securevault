-- SecureVault initial schema.
-- Design notes:
--   * Session tokens are stored only as SHA-256 hashes; a database leak
--     reveals no usable credentials.
--   * blobs.hash is the SHA-256 of the PLAINTEXT content — the content
--     address. The wrapped per-file DEK and content nonce live beside it.
--   * ref_count implements reference-counted deletion for deduplicated
--     content: two users uploading the same bytes share one blob.
--   * audit_events never contain passwords, keys, tokens, or file content.

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username            text NOT NULL UNIQUE,
    password_hash       text NOT NULL,            -- encoded Argon2id string (params + salt + hash)
    role                text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    password_changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,             -- SHA-256 of the opaque token
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Failed login attempts, consulted by the throttling window. Rows are
-- pruned opportunistically; the key is username OR client address.
CREATE TABLE login_failures (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key          text NOT NULL,                   -- "u:<username>" or "ip:<addr>"
    attempted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX login_failures_key_time_idx ON login_failures (key, attempted_at);

-- One row per unique stored content. hash is the storage engine's content
-- address; the ciphertext object on disk is named by this hash.
CREATE TABLE blobs (
    hash        bytea PRIMARY KEY,                -- SHA-256 of plaintext (32 bytes)
    size_bytes  bigint NOT NULL CHECK (size_bytes >= 0),
    wrapped_dek bytea NOT NULL,                   -- DEK encrypted under the KEK (AES-256-GCM)
    ref_count   integer NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- A node is a user-visible file: a named reference to a blob.
CREATE TABLE nodes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob_hash    bytea NOT NULL REFERENCES blobs(hash),
    display_name text NOT NULL,                   -- sanitized; never used as a filesystem path
    mime_type    text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX nodes_owner_id_idx ON nodes (owner_id);
CREATE INDEX nodes_blob_hash_idx ON nodes (blob_hash);

-- Sharing grants. Owners are implicit (nodes.owner_id) and never appear here.
CREATE TABLE grants (
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    grantee_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('editor', 'viewer')),
    granted_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, grantee_id)
);

CREATE INDEX grants_grantee_id_idx ON grants (grantee_id);

-- Append-only audit trail of security-relevant events.
CREATE TABLE audit_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    actor_id   uuid,                              -- NULL for unauthenticated actors
    actor_name text NOT NULL DEFAULT '',
    action     text NOT NULL,                     -- e.g. auth.login, file.download, share.grant
    target     text NOT NULL DEFAULT '',          -- e.g. node id, username; never file content
    result     text NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    reason     text NOT NULL DEFAULT '',
    request_id text NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_at_idx ON audit_events (at);
CREATE INDEX audit_events_actor_id_idx ON audit_events (actor_id);
