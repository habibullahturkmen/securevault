# Operations runbook

Day-2 procedures: keys, accounts, audit review, incident response, backups,
and the pre-submission scan. Commands assume the repository root.

## 1. Master key (KEK) management

The master key wraps every per-file data-encryption key. It is supplied
exclusively through the `SECUREVAULT_MASTER_KEY` environment variable
(64 hex chars = 32 bytes), normally via the git-ignored `.env`.

**Generate:**

```bash
make genkey     # openssl rand -hex 32 — paste into .env
```

**Rules:**

- One key per environment. The demo stack and local dev may share a
  throwaway key; anything holding real data gets its own.
- Never commit, log, echo, or paste the key anywhere durable. gitleaks runs
  on every commit in CI as the backstop, not the primary control.
- The server validates the key at startup and refuses to boot on a missing
  or malformed value — there is no fallback key, by design.

**If the key is lost:** every stored file is permanently unreadable. The
database and blob volume remain intact but hold only ciphertext and wrapped
DEKs that nothing can unwrap. There is no recovery path — this is the
correct security property, stated plainly. Protect `.env` like the data
itself.

**Key rotation (documented limitation):** rotating the KEK requires
unwrapping every `blobs.wrapped_dek` under the old key and re-wrapping under
the new one (the objects themselves would not need re-encryption — only the
small wrapped keys). No tool for this ships in the prototype; note it as
future work in the report rather than claiming rotation support.

## 2. Account administration

Registration always creates role `user`. The admin role is assigned only
through system configuration (proposal §4.3) — deliberately not via HTTP:

```bash
psql -d securevault -c "UPDATE users SET role='admin' WHERE username='alice';"
# demote the same way with role='user'
```

Admins can list accounts and read the audit log in the UI ("Administration"
button) or via `GET /api/admin/users` / `GET /api/admin/audit`. They cannot
read, share, or delete anyone's files — verify anytime by trying (expect
404s; each attempt lands in the audit log, which is the point).

Removing an account is a manual decision:
`DELETE FROM users WHERE username='...'` cascades to their sessions, nodes,
and grants; blob reference counts are **not** auto-decremented by the
cascade, so prefer deleting the user's files through the API first, then
the account row.

## 3. Audit log review

What to look for, in order of interest:

| Pattern | Meaning |
|---|---|
| `result=denied, reason=no_grant` bursts from one actor | someone probing other users' file IDs |
| `auth.login denied, reason=throttled` | credential-stuffing attempt hit the limiter |
| `result=error, reason=integrity_failure` | **tampering or disk corruption — treat as an incident (§4)** |
| `admin.access denied` | non-admin poked an admin endpoint |
| `share.grant` / `share.revoke` trail | who had access to a file, and when, for any dispute |

Queries the UI doesn't cover:

```sql
-- denials in the last 24h grouped by actor
SELECT actor_name, action, count(*) FROM audit_events
WHERE result='denied' AND at > now() - interval '24 hours'
GROUP BY 1,2 ORDER BY 3 DESC;

-- full history of one file
SELECT at, actor_name, action, result, reason FROM audit_events
WHERE target = '<node-uuid>' ORDER BY at;
```

The table is append-only by convention and the app role only ever INSERTs;
for stronger tamper-evidence of the log itself (out of scope for the
prototype), revoke UPDATE/DELETE on `audit_events` from the app's database
role.

## 4. Incident: integrity failure

A download returning `500 stored object failed integrity verification`
means the ciphertext on disk no longer authenticates — tampering, bit rot,
or a partial disk failure. The system has already done the important part:
**no plaintext was released, and the event is audited.**

1. Identify the object: the audit row's `target` is the node ID;
   `SELECT encode(blob_hash,'hex'), display_name FROM nodes WHERE id='<target>';`
2. Check scope: try downloads of other files; grep the audit log for more
   `integrity_failure` rows. One object → likely corruption; many → suspect
   the host or the volume.
3. The object file is `data/objects/<hh>/<hash>.obj`. Do not "fix" it in
   place; preserve it for analysis (`cp` it out).
4. Recovery = restore that object file from backup (§6) — content
   addressing guarantees the restored bytes are the right ones: if the
   restored file decrypts and re-hashes to its own name, it is exactly the
   original.
5. If tampering is suspected rather than rot, treat the host as compromised
   (see the threat-model honesty note in
   [architecture.md](architecture.md) §6.7).

## 5. OWASP ZAP baseline scan (pre-submission gate)

The proposal (§5.3, §7) commits to a ZAP baseline scan with all
medium-or-higher findings resolved or justified before submission.

**Via CI (preferred):** GitHub → Actions → `ci` → *Run workflow*. The
`zap-baseline` job builds the embedded binary, boots it against a Postgres
service, and runs `zaproxy/action-baseline`; the HTML report is attached as
a workflow artifact. Do this on the final commit and attach the report to
the evidence bundle.

**Locally, against the compose stack:**

```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
docker run --rm --network host -v "$PWD:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://localhost -I -r zap-report.html
```

For each finding: fix it, or record the justification (finding, why it is
acceptable, where it is mitigated) in the report — silent ignores fail the
proposal's own standard.

## 6. Backups

Three things constitute the system state; back up all three or none is
recoverable:

| What | Where | How |
|---|---|---|
| Metadata + wrapped DEKs + audit | PostgreSQL | `pg_dump securevault > backup.sql` (compose: `docker compose -f deploy/docker-compose.yml --env-file .env exec db pg_dump -U securevault securevault > backup.sql`) |
| Ciphertext objects | `data/` (dev) / `blob-data` volume (compose) | plain file copy — objects are immutable once written, so rsync is safe and incremental |
| Master key | `.env` | store separately from the other two — a backup bundle containing all three is plaintext-equivalent |

Restore order: database first, then objects, then start the server with the
key. Content addressing self-verifies the object store: any restored object
that decrypts and re-hashes correctly is bit-for-bit the original; any that
doesn't will be caught on first read and audited.

Consistency note: a live copy taken mid-upload can at worst capture an
orphan object file (invisible, harmless — see
[architecture.md](architecture.md) §4). It can never capture a metadata row
whose object is missing, because objects are published before their
metadata commits.

## 7. Routine maintenance

- **Expired sessions**: rows linger after `expires_at` (validation already
  rejects them). Housekeeping:
  `DELETE FROM sessions WHERE expires_at < now();`
- **Login failures**: pruned opportunistically on every throttle check;
  no action needed.
- **Orphan objects** (post-crash leftovers): reclaimed automatically when
  the same content is re-uploaded. To sweep manually, list files under
  `data/objects/` whose hex name is absent from
  `SELECT encode(hash,'hex') FROM blobs;` — deleting those is always safe.
- **Dependencies**: `go get -u ./... && go mod tidy` and `pnpm update` on a
  branch; the CI gates (race tests, Semgrep) are the regression net.
