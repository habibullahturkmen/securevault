# API reference

Base URL: same origin as the UI (`/api/...`). All request and response
bodies are JSON except upload (multipart) and download (raw bytes).

## Conventions

### Authentication

Session cookie `sv_session` — set by login, `HttpOnly`, `SameSite=Strict`,
`Secure` outside dev mode, 24 h lifetime. Endpoints marked **auth** return
`401 {"error":"authentication required"}` without a valid session.

### CSRF

Endpoints marked **csrf** additionally require the header
`X-CSRF-Token: <value of the sv_csrf cookie>` (double-submit; the cookie is
set at login and is readable by the SPA). Missing or wrong token →
`403 {"error":"missing CSRF token" | "invalid CSRF token"}`.

### Errors

Every error is `{"error": "<message>"}` with an appropriate status. Three
deliberate uniformities:

- **401** login failure is identical for unknown username and wrong
  password, with equalized timing.
- **404** is returned both when a file does not exist and when the caller
  has no grant on it — the two are indistinguishable to prevent resource
  enumeration. The audit log records which one actually happened.
- **500** is always the bare string `internal error` (or the controlled
  integrity message below); internals never leak.

Malformed request bodies (unknown JSON fields, trailing data, >16 KiB) →
`400 {"error":"malformed request body"}`. Path IDs failing UUID validation →
404 without touching the database.

### The file object

```json
{
  "id":        "07442aca-5f39-4eb6-b4d5-6db7f2e165b1",
  "name":      "report.txt",
  "mimeType":  "text/plain",
  "size":      18,
  "owner":     "alice",
  "myRole":    "owner",            // owner | editor | viewer
  "createdAt": "2026-08-11T23:40:18.68Z",
  "updatedAt": "2026-08-11T23:40:18.68Z"
}
```

## Health

### GET /api/health
`200 {"status":"ok"}`. No auth. Used by CI and the ZAP scan bootstrap.

## Authentication endpoints

### GET /api/auth/registration
`200 {"mode": "open"|"invite"|"closed", "acceptingRegistrations": bool, "inviteRequired": bool}`.
No auth. Tells the sign-up form which fields to show; reveals the policy,
never any account. On an empty database `acceptingRegistrations` is `true`
in every mode (bootstrap, see below).

### POST /api/auth/register
Body: `{"username": "...", "password": "...", "inviteCode": "..."}` —
`inviteCode` is optional and only consulted when the server runs with
`REGISTRATION_MODE=invite` (case-insensitive; spaces and dashes ignored).
Username: 3–32 chars, `[a-z0-9][a-z0-9_.-]*`. Password: 8–128 chars, no
composition rules (NIST SP 800-63B). New accounts always get role `user`.

Policy (`REGISTRATION_MODE`, `MAX_USERS`): the first account on an empty
database is always admitted (bootstrap); after that `closed` refuses,
`invite` needs an unused, unexpired, unrevoked code (consumed atomically
with the insert), and `MAX_USERS` caps the total in any mode. Every denial
is audited as `auth.register denied` with the reason.

| Status | Meaning |
|---|---|
| 201 | `{"id","username","role"}` |
| 400 | username or password policy violation (message says which) |
| 403 | `registration is closed` / `an invite code is required to register` / `invite code is invalid, expired, or already used` / `the account limit has been reached` |
| 409 | `username is already taken` |

### POST /api/auth/login
Body: `{"username": "...", "password": "..."}`
Success sets both cookies (fresh session token — rotation on every login).

| Status | Meaning |
|---|---|
| 200 | `{"id","username","role"}` + `Set-Cookie: sv_session, sv_csrf` |
| 401 | `invalid username or password` (uniform, timing-equalized) |
| 429 | `too many failed attempts; try again later` — ≥10 failures for the username or ≥30 for the client address within 15 min |

### POST /api/auth/logout — auth
Invalidates the presented session server-side and clears both cookies.
`200 {"status":"logged out"}`.

### POST /api/auth/password — auth + csrf
Body: `{"currentPassword": "...", "newPassword": "..."}`
On success **all** sessions for the account are revoked and the response
sets a fresh session (the current client stays signed in; every other
device is signed out).

| Status | Meaning |
|---|---|
| 200 | `{"status":"password changed"}` + rotated cookies |
| 400 | new password fails policy |
| 401 | current password wrong (audited) |

### GET /api/auth/me — auth
`200 {"id","username","role"}` for the session's user.

## File endpoints

Role requirements refer to the sharing matrix (owner / editor / viewer);
"—" in the matrix means the caller receives 404.

### GET /api/files — auth
`200 {"files": [FileObject, …]}` — everything the caller owns or holds a
grant on, newest first, each with the caller's `myRole`.

### POST /api/files — auth + csrf
`multipart/form-data` with a single part named `file` (filename and
part `Content-Type` are used for validation).

| Status | Meaning |
|---|---|
| 201 | FileObject |
| 400 | no file part; malformed content type; **declared MIME does not match the magic-byte signature** (audited as `type_mismatch`) |
| 413 | content exceeds `MAX_UPLOAD_BYTES` (enforced while receiving; no partial data remains) |

Identical content (byte-for-byte) is deduplicated server-side; the uploader
still gets their own independent file entry.

### GET /api/files/{id} — auth, any role
`200 {"file": FileObject, "shares": [{"username","role"}, …]?}` —
`shares` is present only when the caller is the owner; grantees see the
file, not who else has it.

### GET /api/files/{id}/download — auth, any role
`200` raw verified plaintext with headers:
`Content-Disposition: attachment; filename=...`, original `Content-Type`,
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.

| Status | Meaning |
|---|---|
| 404 | no such file **or** no grant (uniform) |
| 500 | `stored object failed integrity verification` — tamper/corruption detected; no bytes released; audited as `integrity_failure` |

### PATCH /api/files/{id} — auth + csrf, owner or editor
Body: `{"name": "new-name.txt"}` (sanitized server-side).
`200` updated FileObject.

### DELETE /api/files/{id} — auth + csrf, owner only
Removes the caller's file entry; the underlying content is removed only
when its last reference disappears. `200 {"status":"deleted"}`.

### PUT /api/files/{id}/shares — auth + csrf, owner only
Body: `{"username": "grantee", "role": "editor" | "viewer"}` — upsert
(re-granting changes the role). Cannot grant to the owner; grantee must be
a registered user (`400` otherwise). `200 {"status":"shared"}`.

### DELETE /api/files/{id}/shares/{username} — auth + csrf, owner only
`200 {"status":"revoked"}`; `400 {"error":"validation failed: no such grant"}`
if there was nothing to revoke.

## Administration endpoints — auth + admin role

Non-admin callers receive **404** (not 403 — admin endpoints do not reveal
their existence) and the attempt is audited as `admin.access denied`.
Reminder: the admin role carries **no** file access; these endpoints serve
account and audit review only.

### GET /api/admin/users
`200 {"users": [{"id","username","role","createdAt"}, …]}`.

### GET /api/admin/audit?limit=N&before=ID
`200 {"events": [{"id","at","actor","action","target","result","reason","requestId"}, …], "nextBefore": ID|null}`,
newest first. `limit` 1–1000 (default 50). Paging is keyset on the
append-only event `id`: pass a page's `nextBefore` as `before` to get the
next older page; `null` means there is nothing older. Keyset paging stays
consistent while new events keep arriving. `400` for an out-of-range
`limit` or a non-positive `before`.

Actions currently emitted: `auth.register`, `auth.login`, `auth.logout`,
`auth.password_change`, `file.upload`, `file.view`, `file.download`,
`file.rename`, `file.delete`, `file.share`, `share.grant`, `share.revoke`,
`invite.create`, `invite.revoke`, `invite.redeem`, `admin.access`.
Results: `ok`, `denied`, `error`.

### GET /api/admin/invites
`200 {"invites": [{"id","note","createdBy","createdAt","expiresAt","usedBy","usedAt","revokedAt","status"}, …]}`,
newest first (200 most recent). `status` is `active`, `used`, `revoked`, or
`expired`. The code itself is never listed — like session tokens it is
stored only as a SHA-256 hash.

### POST /api/admin/invites — csrf
Body: `{"note": "...", "ttlHours": N}` — both optional; `note` ≤ 64 chars,
`ttlHours` 1–720 (default 168 = 7 days).

| Status | Meaning |
|---|---|
| 201 | `{"code": "<26-char base32>", "invite": {…as above…}}` — the code appears in this response **only** |
| 400 | lifetime or note out of range |

### DELETE /api/admin/invites/{id} — csrf
Revokes an active invite. `200 {"status":"revoked"}`; `404 invite not found`
for unknown, malformed, used, or already-revoked ids.

## Cookie reference

| Cookie | Contents | Flags | Purpose |
|---|---|---|---|
| `sv_session` | 256-bit opaque token (stored server-side as SHA-256) | `HttpOnly`, `SameSite=Strict`, `Secure`*, `Path=/`, 24 h | session |
| `sv_csrf` | 256-bit random value | `SameSite=Strict`, `Secure`*, `Path=/`, 24 h — **not** HttpOnly | CSRF double-submit |

\* `Secure` is disabled only when `ENV=dev` (plain-HTTP localhost).

## Worked example (curl)

```bash
B=http://127.0.0.1:8080
curl -s -X POST $B/api/auth/register -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"a strong passphrase"}'
curl -s -c jar.txt -X POST $B/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"a strong passphrase"}'
CSRF=$(grep sv_csrf jar.txt | awk '{print $NF}')
curl -s -b jar.txt -H "X-CSRF-Token: $CSRF" \
     -F "file=@notes.txt;type=text/plain" $B/api/files
curl -s -b jar.txt $B/api/files          # list; grab an "id"
curl -sOJ -b jar.txt $B/api/files/<id>/download
```
