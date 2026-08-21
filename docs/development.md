# Development guide

## One-time setup

```bash
make db-create        # creates securevault + per-package test databases
cp .env.example .env
make genkey           # generates a 32-byte hex master key
# paste the key into .env as SECUREVAULT_MASTER_KEY
```

`.env` is git-ignored and gitleaks scans every commit in CI, so a real key
never reaches the repository.

## The two-terminal workflow

Development runs fully locally — no Docker involved:

```bash
make dev       # terminal 1: Go API on http://127.0.0.1:8080
make web-dev   # terminal 2: Vite dev server on http://localhost:5173
```

Open **http://localhost:5173** (the Vite port, not the Go port).

How the two servers cooperate:

- **Terminal 2 (Vite)** serves the React app with hot module reload — edit a
  `.tsx` file and the browser updates in ~50 ms without losing state. No Go
  rebuild is involved when you work on the UI.
- **`vite.config.ts` proxies `/api` to the Go server.** Any request the app
  makes to `/api/...` is transparently forwarded to `127.0.0.1:8080`. The
  browser sees a single origin, so the session cookie, the CSRF double-submit
  cookie, and `SameSite=Strict` all behave exactly as they do in production.
- **Terminal 1 (Go)** is a dev build: no UI is embedded (`web/embed_off.go`
  returns nil, so the binary answers only `/api` routes). On startup it
  applies any pending embedded SQL migrations, so after pulling a branch the
  schema is always current — there is no separate migrate step, ever.

Editing Go code: stop terminal 1 and `make dev` again (or use a watcher like
`air` if you prefer; the Makefile stays agnostic).

## Database migrations

Schema changes are numbered SQL files in `internal/database/migrations/`
(`0002_short_description.sql`, …). They are embedded into the binary and
applied automatically, in order, each inside its own transaction, guarded by
a Postgres advisory lock. Postgres DDL is transactional: a failed migration
rolls back completely and the server refuses to start.

Rules:

- Never edit an applied migration — add a new one (fix-forward).
- Keep each file small and reviewable; migrations are security artifacts
  that reviewers read in PRs.

## Tests

```bash
make test     # everything; DB-backed tests skip if the test DBs are absent
make race     # the same under the race detector — this is the CI gate
make check    # race + vet + gitleaks + semgrep, mirroring CI exactly
```

Test layout:

| Package            | What it proves                                                            |
|--------------------|---------------------------------------------------------------------------|
| `internal/storage` | round-trips, tamper/truncation/relocation attacks, crash orphan recovery, dedup, size limits, concurrency |
| `internal/auth`    | Argon2id + PHC parsing; adversarial suite: uniform errors, throttling, rotation, revocation, expiry, audit trail |
| `internal/authz`   | the exhaustive role × action authorization matrix, deny-by-default cases  |
| `internal/files`   | filename sanitization, MIME/magic-byte validation                          |
| `internal/api`     | HTTP integration: endpoint-by-role matrix, CSRF, type spoofing, traversal names, oversize, bit-flip integrity attack, dedup semantics, session hygiene, security headers, malformed input |

Each DB-backed package appends a suffix to `TEST_DATABASE_URL`
(`…_auth`, `…_api`) so concurrently running packages cannot truncate each
other's tables. `make db-create` creates all of them.

## Production build, locally

```bash
make build    # pnpm build → go build -tags embedui → bin/securevault
```

This produces the single self-contained binary described in
[production.md](production.md). To try it, source `.env` and run
`./bin/securevault`, then open http://127.0.0.1:8080 — you are now serving
the embedded UI, exactly what the Docker image runs.

**The one gotcha:** the embedded UI is a snapshot taken at `go build` time.
If you change React code and rebuild only the Go binary (skipping
`pnpm build`), you will serve stale UI. `make build` and the Dockerfile
always run the two steps in the right order; the trap only exists if you
hand-run them individually.

## Promoting an administrator

Accounts register with the `user` role. The admin role is assigned through
system configuration (proposal §4.3), i.e. deliberately not exposed over
HTTP:

```bash
psql -d securevault -c "UPDATE users SET role = 'admin' WHERE username = 'someone';"
```

Registration is `open` in development (`.env.example`). To exercise the
invite flow locally, set `REGISTRATION_MODE=invite` in `.env`, restart
`make dev`, and note that the first account on an empty database can still
register — promote it, then issue codes from **Administration → Invites**.
