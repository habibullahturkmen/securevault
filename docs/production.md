# Production build and deployment

## The embedded frontend: how it works

The production artifact is **one static Go binary** that contains the API,
the storage engine, the database migrations, and the entire web interface.

Build time, two steps in a fixed order:

1. `pnpm build` (in `web/`) — Vite compiles the React + TypeScript app into
   plain static files under `web/dist/`: an `index.html`, one hashed JS
   bundle, one CSS file.
2. `go build -tags embedui` — the `embedui` build tag selects
   `web/embed_on.go`, whose directive

   ```go
   //go:embed all:dist
   ```

   makes the compiler copy every byte of `web/dist/` into the executable.
   The result is `bin/securevault` (~16 MB) with no runtime dependency on
   Node, files on disk, or a CDN.

Run time:

- Requests under `/api/` hit the JSON handlers.
- Any other path is served from the embedded filesystem; unknown paths fall
  back to `index.html` so client-side routing works.
- Because one process serves both UI and API, the security headers
  (Content-Security-Policy, nosniff, referrer policy, …) are set in exactly
  one place — `internal/api/middleware.go` — and the browser sees a single
  origin, so the `SameSite=Strict` session cookie and the CSRF double-submit
  pair need no cross-origin exceptions.
- A dev build (no tag) embeds nothing: `web/embed_off.go` returns nil and
  the server is API-only, because development uses the Vite dev server
  (see [development.md](development.md)).

Why this fits the project: the proposal (§9, §11) commits to a single static
binary as a simplicity-and-review property. Embedding keeps that promise for
the UI as well — there is no web-server configuration to audit beyond Caddy's
four-line TLS block, and the demo artifact is bit-for-bit what CI built.

## Configuration and the master key

All configuration enters through the environment (see `.env.example`):

| Variable                 | Meaning                                            |
|--------------------------|----------------------------------------------------|
| `SECUREVAULT_MASTER_KEY` | 32-byte hex KEK; wraps every per-file DEK          |
| `DATABASE_URL`           | PostgreSQL connection string                        |
| `DATA_DIR`               | encrypted blob store directory                      |
| `LISTEN_ADDR`            | bind address (behind Caddy: internal only)          |
| `MAX_UPLOAD_BYTES`       | streaming upload limit                              |
| `ENV`                    | `prod` enables `Secure` cookies (TLS required)      |

The master key is generated with `make genkey`, lives in the git-ignored
`.env`, and is validated at startup — the server refuses to boot with a
missing or malformed key rather than falling back to anything. It is never
written to code, database, logs, or audit events; gitleaks in CI enforces
the repository side of that promise. Losing the key means losing every
stored file; treat `.env` accordingly.

## The Docker Compose stack

```bash
cp .env.example .env        # set SECUREVAULT_MASTER_KEY (make genkey)
docker compose -f deploy/docker-compose.yml --env-file .env up --build
```

Then open **https://localhost** and accept Caddy's locally-issued
certificate (`tls internal`). The stack mirrors the proposal's trust zones:

```
browser ──HTTPS──▶ caddy (TLS 1.3, HSTS)          [edge + internal networks]
                     │ reverse_proxy
                     ▼
                   app (single binary, ENV=prod)   [internal network only]
                     │                    │
                     ▼                    ▼
                   postgres:16          /data volume (ciphertext objects)
```

- Only Caddy publishes ports; the app and database are unreachable from the
  host network.
- The app image is distroless and runs as nonroot: no shell, no package
  manager inside the container.
- Postgres data and the blob store live on named volumes and survive
  restarts. Migrations apply automatically when the app boots.
- For a real domain, edit `deploy/Caddyfile`: replace `localhost` with the
  domain and delete `tls internal`; Caddy then provisions certificates
  automatically.

## CI security gates

`.github/workflows/ci.yml` runs on every push and pull request:

| Gate               | Tool                                    |
|--------------------|-----------------------------------------|
| Formatting         | `gofmt -l` (fails on any file)          |
| Static analysis    | `go vet`, Semgrep (`--config auto`)     |
| Secret scanning    | gitleaks over full history              |
| Tests              | `go test -race ./...` against PostgreSQL 16, including the adversarial and integration suites |
| Build              | frontend build + `go build -tags embedui` |
| Dynamic scan       | OWASP ZAP baseline (manual trigger: Actions → ci → Run workflow) |

`make check` runs the same gates locally so a push never surprises you.
