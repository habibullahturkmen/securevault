-- Invite codes for restricted registration (REGISTRATION_MODE=invite).
-- Like session tokens, codes are stored only as SHA-256 hashes: the
-- plaintext is shown to the issuing administrator exactly once and a
-- database leak yields nothing redeemable. One code admits one account.

CREATE TABLE invites (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash  bytea NOT NULL UNIQUE,             -- SHA-256 of the plaintext code
    note       text NOT NULL DEFAULT '',          -- admin's label, e.g. who it is for
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    used_at    timestamptz,
    revoked_at timestamptz
);

CREATE INDEX invites_created_at_idx ON invites (created_at);
