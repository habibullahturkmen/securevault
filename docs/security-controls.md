# Security controls: threat → control → test traceability

Every protection the proposal claims is paired with an implemented control
and an automated test that attacks it (proposal §6–7). This table is the
traceability map; run `make race` to execute all of it.

## STRIDE coverage

| Threat (STRIDE) | Control | Where implemented | Test that attacks it |
|---|---|---|---|
| **Spoofing** — credential guessing, session theft | Argon2id (64 MiB, t=3, p=4, PHC format); uniform errors with timing equalization; opaque 256-bit tokens stored SHA-256-hashed; HttpOnly/Secure/SameSite=Strict cookies; rotation on login and password change; sliding-window throttling (10/username, 30/address per 15 min) | `internal/auth` | `TestUniformCredentialErrors`, `TestThrottlingAfterRepeatedFailures`, `TestAddressThrottling`, `TestSessionRotationOnLogin`, `TestSessionHygiene` (cookie attrs, hashed-at-rest, replay after logout) |
| **Tampering** — ciphertext or metadata modified on disk | AES-256-GCM tag verification; SHA-256 re-verification against the content address on every read; content hash bound as GCM associated data (objects cannot be relocated); plaintext never released on failure | `internal/storage` | `TestTamperedCiphertext` (bit-flips in every object region), `TestTruncatedObject`, `TestObjectRelocationAttack`, `TestWrongMasterKey`, HTTP-level `TestIntegrityAttack` |
| **Repudiation** — user denies an action | Append-only audit events with actor, action, target, result, reason, request id for the full lifecycle including denials and integrity failures | `internal/audit`, recorded by `auth`, `files`, `api` | `TestAuditTrailForAuthEvents`, audit assertions inside `TestEndpointRoleMatrix` and `TestIntegrityAttack` |
| **Information disclosure** — reading another user's file or plaintext from disk | Centralized deny-by-default `authz.Can`; denials normalized to 404 (no resource enumeration); encryption at rest; attachment-only downloads with nosniff; admin role has no path to file content | `internal/authz`, `internal/files`, `internal/api` | `TestAuthorizationMatrix`, `TestEndpointRoleMatrix` (owner/editor/viewer/unrelated/admin/anonymous × 5 endpoints), `TestStoredObjectIsCiphertext` |
| **Denial of service** — oversized/repeated uploads | Streaming size limit enforced while receiving (limit+1 read); `MaxBytesReader` on every body; temp files removed on rejection; login throttling | `internal/storage`, `internal/api`, `internal/auth` | `TestSizeLimitEnforcedWhileReceiving`, `TestOversizedUploadRejected` (also asserts zero residual files) |
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
