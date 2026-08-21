# SecureVault documentation

Start here. Each document is self-contained; together they cover the system
from design rationale to day-to-day operation.

| Document | What it covers | Read it when… |
|---|---|---|
| [architecture.md](architecture.md) | Trust zones, components, database schema, the upload/download lifecycles, and the reasoning behind every major design decision (two-phase writes, hash-as-AAD, dedup, embedded migrations, single binary) | you need to explain *why* the system is built this way — e.g. in the presentation Q&A |
| [api.md](api.md) | Every HTTP endpoint: request/response shapes, status codes, authentication and CSRF requirements, cookie and error semantics | you are writing client code or testing an endpoint by hand |
| [development.md](development.md) | One-time setup, the two-terminal dev workflow (Go + Vite hot reload), migrations, running tests, promoting an admin | you are setting up a laptop to work on the project |
| [production.md](production.md) | How the embedded frontend works, configuration reference, the Docker Compose stack, deploying on Coolify, CI gates | you are building the release artifact, running the demo, or deploying to a server |
| [testing.md](testing.md) | The complete test inventory, what each adversarial test attacks, and how to capture evidence for the report | you are collecting proof for §7 of the report |
| [operations.md](operations.md) | Runbook: master-key handling, backups, audit review, integrity-failure response, the pre-submission ZAP scan | something needs operating, recovering, or checking |
| [security-controls.md](security-controls.md) | The STRIDE threat → control → test traceability table | you need the one-page map from claim to evidence |

## Daily commands

```bash
# develop
make dev        # terminal 1 — Go API on http://127.0.0.1:8080 (applies migrations)
make web-dev    # terminal 2 — Vite dev server on http://localhost:5173 (hot reload)

# test
make test       # full suite; DB-backed tests skip if test databases are absent
make race       # the same under the race detector — the CI gate
make check      # race + vet + gitleaks + semgrep, mirroring CI

# build & demo
make build      # pnpm build → go build -tags embedui → bin/securevault (single binary)
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build   # https://localhost
docker compose -f deploy/docker-compose.yml --env-file .env down            # stop the stack

# utilities
make genkey     # generate a master key for .env
make db-create  # create dev + per-package test databases
```

## The system in one paragraph

SecureVault stores every file under the SHA-256 hash of its content, so
identity and integrity are the same fact: any modification changes the hash
and is caught on the next read. Before touching disk, content is encrypted
with AES-256-GCM under a fresh per-file key, which is itself wrapped by a
master key that exists only in protected configuration. Authentication is
built from first principles (Argon2id, hashed opaque sessions, throttling),
every file-touching request passes through a single deny-by-default
authorization function, and every security-relevant event — including every
denial — lands in an append-only audit log. The deliverable is one static Go
binary containing the API, the storage engine, the schema migrations, and
the React web interface.

## Team ownership (proposal §10)

| Area | Lead |
|---|---|
| Architecture, storage engine, CI pipeline | Habibullah Turkmen |
| Authentication and sessions | Bernard Appiah |
| File API, sharing, centralized authorization | Soumita Bose |
| Web interface, upload validation, test evidence | Sahil Zainul Aabeddin Kazi |

All members cross-review pull requests; any member should be able to explain
any component using these documents.
