# Security controls: threat → control → test traceability

Every protection the proposal claims is paired with an implemented control
and an automated test that attacks it (proposal §6–7). This table is the
traceability map; run `make race` to execute all of it.

## Major controls: file and line evidence

These are the shortest implementation paths to show during a demonstration.
Line numbers refer to the source at this revision.

### 1. Password hashing

- `internal/auth/password.go:14-37` defines the Argon2id parameters and creates
  a salted PHC-formatted password hash.
- `internal/auth/password.go:40-49` verifies a supplied password using a
  constant-time comparison.
- `internal/auth/service.go:84-113` validates a new password, hashes it, and
  inserts only `password_hash` into PostgreSQL.
- `internal/auth/service.go:164-182` retrieves the stored hash and verifies it
  during login; the plaintext password is never queried from the database.
- `internal/database/migrations/0001_init.sql:11-18` defines the users table
  with `password_hash`, not a plaintext-password column.

### 2. API security

- `web/src/api.ts:67-86` is the frontend JSON client. It serializes request
  bodies as JSON, reads JSON responses, and sends the CSRF header on mutations.
- `internal/api/server.go:53-106` defines the REST-style routes and applies
  authentication, CSRF, and administrator middleware.
- `internal/api/server.go:189-216` validates UUID route values, limits JSON
  bodies to 16 KiB, rejects unknown fields, and emits JSON responses.
- `internal/api/middleware.go:61-78` applies CSP, nosniff, same-origin, referrer,
  and permissions security headers.
- `internal/api/middleware.go:81-129` validates sessions, checks double-submit
  CSRF tokens in constant time, and gates administrator routes.
- `internal/authz/authz.go:42-83` is the deny-by-default file permission matrix.
- `internal/files/files.go:253-270` re-authorizes each file operation on the
  server; frontend button visibility is not trusted.
- `deploy/Caddyfile:6-14` terminates TLS and adds HSTS.

### 3. Secure sessions

- `internal/auth/token.go:10-28` creates 256-bit random opaque session tokens
  and hashes them with SHA-256 before database storage.
- `internal/auth/service.go:46-53` sets the 30-minute inactivity timeout and
  four-hour absolute lifetime.
- `internal/auth/service.go:237-274` stores only the token hash and enforces
  both deadlines while updating `last_seen_at`.
- `internal/auth/service.go:277-287` invalidates the server-side session on
  logout; `internal/auth/service.go:290-339` revokes all sessions and rotates
  the identifier after a password change.
- `internal/api/server.go:145-183` sets and clears `HttpOnly`, `Secure`,
  `SameSite=Strict` session cookies and issues a separate CSRF cookie.
- `internal/database/migrations/0001_init.sql:20-29` stores token hashes and the
  absolute deadline; `internal/database/migrations/0003_session_timeouts.sql:1-12`
  adds and initializes the inactivity timestamp.

### 4. Encryption at rest

- `internal/config/config.go:40-67` fails startup unless the environment
  supplies a valid 32-byte master key.
- `internal/storage/crypto.go:18-87` generates per-object data-encryption keys
  and implements AES-256-GCM encryption, decryption, key wrapping, and tag
  verification.
- `internal/storage/store.go:99-163` hashes plaintext, encrypts it with a fresh
  DEK and nonce, and writes only the encrypted object to disk.
- `internal/storage/store.go:203-245` unwraps, decrypts, authenticates, and
  SHA-256 re-verifies an object before returning any plaintext.
- `internal/storage/store.go:270-273` derives disk paths from hashes rather
  than user-controlled filenames.
- `internal/database/migrations/0001_init.sql:41-60` stores the wrapped DEK and
  sanitized metadata; plaintext file content is not stored in PostgreSQL.
- `internal/files/files.go:315-336` authorizes a download before calling the
  decrypting storage operation. An unauthorized request never reaches
  decryption.

### Malware scanning status

ClamAV or another antivirus scanner is **not currently implemented**. Uploads
receive size, filename, MIME-signature, encryption, and authorization checks,
but they are not scanned for malware. Do not claim antivirus scanning as an
implemented control during the demonstration.

## STRIDE coverage

| Threat (STRIDE) | Control | Where implemented | Test that attacks it |
|---|---|---|---|
| **Spoofing** — credential guessing, session theft | Argon2id (64 MiB, t=3, p=4, PHC format); uniform errors with timing equalization; opaque 256-bit tokens stored SHA-256-hashed; HttpOnly/Secure/SameSite=Strict cookies; 30-minute inactivity and four-hour absolute timeouts; rotation on login and password change; sliding-window throttling (10/username, 30/address per 15 min) | `internal/auth` | `TestUniformCredentialErrors`, `TestThrottlingAfterRepeatedFailures`, `TestAddressThrottling`, `TestSessionRotationOnLogin`, `TestExpiredSessionRejected`, `TestIdleSessionRejected`, `TestSessionHygiene` (cookie attrs, hashed-at-rest, replay after logout) |
| **Tampering** — ciphertext or metadata modified on disk | AES-256-GCM tag verification; SHA-256 re-verification against the content address on every read; content hash bound as GCM associated data (objects cannot be relocated); plaintext never released on failure | `internal/storage` | `TestTamperedCiphertext` (bit-flips in every object region), `TestTruncatedObject`, `TestObjectRelocationAttack`, `TestWrongMasterKey`, HTTP-level `TestIntegrityAttack` |
| **Repudiation** — user denies an action | Append-only audit events with actor, action, target, result, reason, request id for the full lifecycle including denials and integrity failures | `internal/audit`, recorded by `auth`, `files`, `api` | `TestAuditTrailForAuthEvents`, audit assertions inside `TestEndpointRoleMatrix` and `TestIntegrityAttack` |
| **Information disclosure** — reading another user's file or plaintext from disk | Centralized deny-by-default `authz.Can`; denials normalized to 404 (no resource enumeration); encryption at rest; attachment-only downloads with nosniff; admin role has no path to file content | `internal/authz`, `internal/files`, `internal/api` | `TestAuthorizationMatrix`, `TestEndpointRoleMatrix` (owner/editor/viewer/unrelated/admin/anonymous × 5 endpoints), `TestStoredObjectIsCiphertext` |
| **Denial of service** — oversized/repeated uploads | Streaming size limit enforced while receiving (limit+1 read); `MaxBytesReader` on every body; temp files removed on rejection; login throttling | `internal/storage`, `internal/api`, `internal/auth` | `TestSizeLimitEnforcedWhileReceiving`, `TestOversizedUploadRejected` (also asserts zero residual files) |
| **Abuse — unrestricted account creation** (spam accounts, storage exhaustion, footprint for credential attacks) | Registration policy: `REGISTRATION_MODE` open/invite/closed with admin-issued one-time invite codes (128-bit, base32, stored SHA-256-hashed, expiring, revocable, consumed atomically with the insert), `MAX_USERS` ceiling, bootstrap-only exception on an empty database; every denial audited with a reason | `internal/auth/registration.go`, `internal/api/handlers_admin.go` | `TestBootstrapIgnoresClosedMode`, `TestInviteLifecycle`, `TestMaxUsersEnforced`, `TestRegistrationDenialsAreAudited`, HTTP-level `TestRegistrationClosed`, `TestInviteFlowOverHTTP` |
| **Elevation of privilege** — user invokes admin functions or escalates a grant | Admin endpoints behind `requireAdmin` (denied = 404 + audit); share/delete restricted to owners by the matrix; viewers cannot rename; grants grantable only by owners | `internal/authz`, `internal/api` | `TestAuthorizationMatrix`, `TestEndpointRoleMatrix`, `TestAdministrationCheck`, `TestDenyByDefault` |
| **Path traversal / stored XSS** | Storage paths derive exclusively from content hashes; filename sanitization to display metadata; strict CSP (`default-src 'self'`, no inline script/style); attachment-only responses; React output encoding | `internal/storage.objectPath`, `internal/files/validate.go`, `internal/api/middleware.go` | `TestTraversalFilenameNeutralized` (including a walk of the data dir), `TestSanitizeFilename`, `TestSecurityHeadersPresent` |
| **SQL injection** | Parameterized queries exclusively (pgx); strict JSON schemas (`DisallowUnknownFields`, size caps); UUID validation before queries | all query sites | `TestMalformedInputRejected`; Semgrep + ZAP in CI |
| **Improper input** — malformed, overlong, inconsistently typed values | Strict schemas, length limits, fail-closed error handling without stack traces (panic recovery middleware) | `internal/api` | `TestMalformedInputRejected`, `TestMalformedHashRejected`, malformed-id cases |
| **Type spoofing** — disallowed file renamed to an allowed extension | Declared MIME checked against magic-byte signature; mismatch rejects | `internal/files/validate.go` | `TestTypeSpoofingRejected`, `TestValidateContent` |
| **Crash consistency** — server dies mid-write | Two-phase writes: ciphertext published via temp + fsync + rename *before* the metadata commit; orphans are invisible and reclaimed on re-upload; deletes dereference before unlink | `internal/storage`, `internal/files` | `TestStagedObjectInvisibleUntilCommit`, `TestCommitReplacesOrphan`, `TestConcurrentPutSameContent` (race detector) |

## Key handling summary

- Master key (KEK): environment only, validated at startup, never persisted;
  gitleaks gates every commit.
- Per-file DEKs: generated fresh per upload, wrapped with AES-256-GCM under
  the KEK with the content hash as associated data, stored only in wrapped
  form in PostgreSQL.
- Session tokens: 256-bit random, stored only as SHA-256 hashes
  (`TestSessionHygiene` proves the cookie value never appears in the DB).
- Passwords: Argon2id PHC strings with per-password salts
  (`TestUniqueSalts`).

## Deduplication semantics

Identical content uploaded by different users shares one encrypted object
under one wrapped DEK; each user references it through their own node.
Deletion decrements the reference count and removes the object only at zero
(`TestDeduplication` at both the storage and HTTP layers).
