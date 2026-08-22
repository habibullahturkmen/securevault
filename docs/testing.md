# Testing guide and evidence map

Every protection the proposal claims is paired with a test that attacks it
(proposal §7: "every claimed protection is paired with a test that attacks
it"). This document inventories those tests, explains what each one proves,
and shows how to capture evidence for the report.

## Running the suite

```bash
make db-create   # once: dev DB + securevault_test_auth + securevault_test_api
make test        # full suite
make race        # full suite under the race detector — this is the CI gate
make check       # race + vet + gitleaks + semgrep (mirrors CI exactly)

# verbose evidence run for the report:
TEST_DATABASE_URL=postgres://securevault:securevault@localhost:5432/securevault_test \
  go test -race -v ./... 2>&1 | tee test-evidence.txt
```

DB-backed tests **skip** (they do not fail) when `TEST_DATABASE_URL` is
unset, so the storage/authz/validation tests still run anywhere. Each
package appends its own suffix (`_auth`, `_api`) to the URL because
`go test ./...` runs packages concurrently and each package truncates its
tables — sharing one database caused a real intermittent failure during
development (a mid-run truncation wiped another package's throttling
state), which is exactly the class of bug the convention prevents.

Expect the auth package to take ~15–20 s: every login in those tests pays
real Argon2id cost (64 MiB, t=3). That slowness is itself a control working.

## Proposal §7 scenarios → concrete tests

| Proposal scenario | Test(s) | Package |
|---|---|---|
| Valid lifecycle (upload → list → download → share → delete; stored object is ciphertext; events logged) | `TestValidLifecycle`, `TestStoredObjectIsCiphertext` | api, storage |
| Deduplication (two accounts, one object; independent deletion) | `TestDeduplication` (HTTP level), `TestDeduplication` (engine level) | api, storage |
| Authentication (uniform failures, throttling, no timing difference) | `TestUniformCredentialErrors`, `TestThrottlingAfterRepeatedFailures`, `TestAddressThrottling` | auth |
| Session handling (cookie attributes; reuse after logout/rotation rejected; DB holds only hashes; idle and absolute deadlines) | `TestSessionHygiene`, `TestSessionRotationOnLogin`, `TestChangePasswordRevokesOtherSessions`, `TestExpiredSessionRejected`, `TestIdleSessionRejected` | api, auth |
| Authorization matrix (every endpoint × every role; denials recorded) | `TestAuthorizationMatrix` (pure matrix), `TestEndpointRoleMatrix` (live HTTP, 6 principals × 5 endpoints + audit assertion) | authz, api |
| Object-level authorization (no grant / viewer / editor against another user's file) | rows of `TestEndpointRoleMatrix`; `TestDenyByDefault` | api, authz |
| Filename / path handling (traversal names neutralized; no user-controlled path) | `TestTraversalFilenameNeutralized` (walks the data dir), `TestSanitizeFilename` | api, files |
| Type spoofing (disallowed content behind an allowed extension) | `TestTypeSpoofingRejected`, `TestValidateContent` | api, files |
| Oversized upload (stream stopped, no object, temp cleaned) | `TestOversizedUploadRejected`, `TestSizeLimitEnforcedWhileReceiving` | api, storage |
| Integrity attack (flip ciphertext bytes → blocked, logged, controlled error) | `TestIntegrityAttack` (HTTP), `TestTamperedCiphertext` (every object region), `TestTruncatedObject` | api, storage |
| Crash consistency (no partially written object ever visible) | `TestStagedObjectInvisibleUntilCommit`, `TestCommitReplacesOrphan`, `TestConcurrentPutSameContent` | storage |
| Application security (static/secret/dynamic scanning) | CI jobs: Semgrep, gitleaks, ZAP baseline (see [operations.md](operations.md)) | — |

## Full inventory by package

### `internal/storage` — engine correctness and attacks
- `TestRoundTrip`, `TestEmptyContent` — identity, size, byte fidelity.
- `TestStoredObjectIsCiphertext` — plaintext never on disk.
- `TestDeduplication` — same address, abort path, temp hygiene.
- `TestSizeLimitEnforcedWhileReceiving` — limit+1 rejection, boundary case.
- `TestStagedObjectInvisibleUntilCommit` — two-phase write invariant.
- `TestTamperedCiphertext` — bit-flips at magic/nonce/body/tag positions;
  every one → `ErrCorrupt`, no plaintext.
- `TestTruncatedObject`, `TestWrongMasterKey` — corruption and wrong-KEK.
- `TestObjectRelocationAttack` — intact ciphertext moved to another content
  address fails (hash-as-AAD binding).
- `TestCommitReplacesOrphan` — crash-orphan reclaimed by re-upload.
- `TestRemove`, `TestDoubleFinalizeRejected` — idempotent delete, API misuse.
- `TestConcurrentPutSameContent`, `TestConcurrentDistinctContent` — the
  race detector patrols these.

### `internal/auth` — credential and session lifecycle
- `TestHashAndVerify`, `TestUniqueSalts`, `TestMalformedHashRejected` —
  Argon2id + PHC parsing (wrong variant/version/params rejected).
- `TestSessionTokens` — entropy, hash length, token≠hash.
- `TestRegisterLoginLogoutLifecycle`, `TestRegistrationPolicy` — happy path
  and policy edges (short names, uppercase, traversal chars, short password,
  duplicates).
- `TestParseRegistrationMode`, `TestBootstrapIgnoresClosedMode`,
  `TestInviteLifecycle` (no code / wrong code / sloppy re-typed code /
  single use / revoked / expired / non-admin issuance / plaintext never
  stored), `TestMaxUsersEnforced`, `TestRegistrationDenialsAreAudited` —
  the registration policy (`REGISTRATION_MODE`, `MAX_USERS`).
- `TestUniformCredentialErrors`, `TestThrottlingAfterRepeatedFailures`
  (correct password still throttled once tripped), `TestAddressThrottling`
  (username spraying), `TestSessionRotationOnLogin`,
  `TestChangePasswordRevokesOtherSessions`, `TestExpiredSessionRejected`,
  `TestIdleSessionRejected`,
  `TestAuditTrailForAuthEvents` (also greps the audit table for password
  leakage).

### `internal/authz` — the matrix
- `TestAuthorizationMatrix` — every principal class × every action with the
  expected outcome written out in full, including admin-gets-nothing.
- `TestDenyByDefault` — undefined actions, unknown grant roles, empty user
  IDs, nil grant maps: all deny.
- `TestAdministrationCheck`.

### `internal/files` — input validation
- `TestSanitizeFilename` — traversal, control bytes, dot-names, length cap.
- `TestValidateContent` — accept and reject tables for MIME vs. magic bytes
  (ZIP-container office formats, text subtypes, unsniffable content).

### `internal/api` — the system over real HTTP
Real server (`httptest`), real PostgreSQL, real storage directory, real
cookie jars per principal. `TestValidLifecycle`, `TestEndpointRoleMatrix`,
`TestCSRFEnforcement` (missing and forged token),
`TestTypeSpoofingRejected`, `TestTraversalFilenameNeutralized`,
`TestOversizedUploadRejected`, `TestIntegrityAttack`, `TestDeduplication`,
`TestSessionHygiene`, `TestSecurityHeadersPresent`,
`TestMalformedInputRejected` (unknown fields, bad UUIDs, oversized JSON),
`TestRegistrationClosed`, `TestInviteFlowOverHTTP` (status endpoint, 403s,
admin issue/list/revoke with CSRF, non-admin 404s, code never listed),
`TestAuditPagination` (keyset walk: newest-first, no overlaps or gaps,
parameter validation).

## Writing new tests — house rules

1. **Attack the control, don't just exercise the feature.** The valuable
   test is the one that tries to break the promise (flip the byte, replay
   the token, forge the header).
2. Assert the *negative* space too: no temp files left, no plaintext in the
   error, no password in the audit table.
3. DB-backed tests: use `testService`/`newEnv` helpers, unique usernames via
   the atomic counter, and never assume table contents from another test.
4. Anything touching goroutines or shared state must pass `make race`, not
   just `make test`.

## Capturing evidence for the report

- **Test run**: the `tee test-evidence.txt` command above; include the
  summary and the `-v` lines for the scenario table's tests.
- **Authorization matrix**: `TestEndpointRoleMatrix` prints nothing when
  green — cite the table in its source (`internal/api/api_test.go`) plus
  the passing run.
- **Tamper demo (live)**: upload a file, flip a byte in
  `data/objects/**/*.obj` with a hex editor, download → controlled 500;
  screenshot the audit row (`result=error, reason=integrity_failure`) in
  the admin UI.
- **Scan reports**: Semgrep/gitleaks output from the CI run logs; ZAP HTML
  report artifact from the manual workflow (see
  [operations.md](operations.md) §5).
- **Architecture figure**: use
  [architecture-diagram.svg](architecture-diagram.svg) (vector — preferred;
  Word and Google Docs embed it crisply) or
  [architecture-diagram.png](architecture-diagram.png) as the report's
  logical-architecture figure; it matches the built system, with the
  narrated walkthrough in [architecture.md](architecture.md) §1 to draw
  captions from.
