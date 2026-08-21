# SecureVault

A secure content-addressed file storage and sharing system. Every stored
object is identified by the SHA-256 hash of its content, encrypted with
AES-256-GCM under a per-file key, and verified on every read — integrity is
structural, not assumed.

Course project for *Cybersecurity Architecture, Design, and Secure Software
Development* (Option 6 — Secure File Storage System).
Team: Bernard Appiah, Soumita Bose, Habibullah Turkmen, Sahil Zainul Aabeddin Kazi.

## What it does

- **Content-addressed storage engine** — SHA-256 identity, automatic
  deduplication, atomic writes (temp + fsync + rename), hash re-verification
  on every read, reference-counted deletion. `internal/storage`
- **Encryption at rest** — AES-256-GCM with a fresh per-file DEK and 96-bit
  nonce; DEKs wrapped by a master key (KEK) supplied via protected
  configuration. The content hash is bound into the ciphertext as GCM
  associated data, so objects cannot be swapped on disk undetected.
- **From-scratch authentication** — Argon2id (64 MiB, t=3, p=4), opaque
  session tokens stored only as SHA-256 hashes, hardened cookies, session
  rotation, login throttling, timing-equalized uniform errors; registration
  policy (open / admin-issued one-time invite codes / closed, plus a user
  cap). `internal/auth`
- **Centralized authorization** — one deny-by-default `authz.Can` function
  decides every file-touching request; sharing roles owner / editor / viewer;
  the admin account role reviews accounts and audit logs but can never read
  file content. `internal/authz`
- **Validation** — streaming upload size limit, filename sanitization, MIME +
  magic-byte signature checks, strict JSON schemas, UUID validation.
- **Audit log** — append-only events (actor, action, target, result, reason)
  for logins, denials, uploads, downloads, deletions, sharing changes, and
  integrity failures. Never contains secrets or file content.
- **Web interface** — React + TypeScript (Vite), embedded into the Go binary,
  operating under a strict Content-Security-Policy.

## Quick start (development)

Prerequisites: Go 1.22+, Node 22 + pnpm, PostgreSQL running locally.

```bash
make db-create                 # create dev + test databases
cp .env.example .env
make genkey                    # paste the output into .env as SECUREVAULT_MASTER_KEY
make dev                       # terminal 1 — API on :8080 (applies migrations)
make web-dev                   # terminal 2 — UI on :5173 with hot reload
```

Open http://localhost:5173. See [docs/development.md](docs/development.md)
for the full workflow, and [docs/production.md](docs/production.md) for the
production build and the Docker Compose demo stack.

Full documentation lives in [docs/](docs/README.md): architecture and design
rationale, the complete API reference, the testing/evidence guide, the
operations runbook, and the security-controls traceability map.

## Tests and security gates

```bash
make test    # full suite (storage, auth, authz matrix, HTTP integration)
make race    # the same under the race detector (CI gate)
make check   # vet + race + gitleaks + semgrep (mirrors CI)
```

The test suite is adversarial by design: bit-level tamper tests, object
relocation attacks, type spoofing, traversal filenames, oversized uploads,
session replay after logout, CSRF omission, and a complete endpoint-by-role
authorization matrix. See
[docs/security-controls.md](docs/security-controls.md) for the
threat → control → test traceability map.

## Repository layout

```
cmd/server/          entrypoint: config, migrations, wiring, HTTP server
internal/config/     environment configuration, master-key validation
internal/database/   pgx pool + embedded SQL migration runner
internal/storage/    content-addressed encrypted storage engine (standalone)
internal/auth/       Argon2id, sessions, throttling, password lifecycle
internal/authz/      THE authorization choke point (authz.Can)
internal/files/      upload/download/share/delete over storage + metadata
internal/api/        HTTP handlers, middleware, CSRF, security headers
internal/audit/      append-only audit event writer
web/                 React + TypeScript UI (embedded via web/embed_on.go)
deploy/              Dockerfile, docker-compose.yml, Caddyfile
docs/                development, production, and security documentation
.github/workflows/   CI: fmt, vet, race tests, Semgrep, gitleaks, ZAP
```
