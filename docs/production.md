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
browser ──HTTPS──▶ caddy (TLS 1.3)                [edge + internal networks]
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

## Deploying on Coolify

[Coolify](https://coolify.io) runs its own reverse proxy (Traefik by
default, optionally Caddy) that terminates TLS and obtains certificates, so
the repository's Caddy service is not needed there. The app is deployed as
a plain **Dockerfile application** from `deploy/Dockerfile`, and PostgreSQL
as a Coolify-managed database resource next to it — no Compose file
involved. Both land on the same Docker network, which is the "internal"
zone of the Compose stack above.

### 1. PostgreSQL

**Project → New Resource → Database → PostgreSQL** (version 16). Leave
"Make it publicly available" **off** — the database should be reachable
only from the Coolify network. After it starts, copy the **internal**
connection URL shown on the database page; it has the form

```
postgres://<user>:<password>@<container-name>:5432/<database>
```

### 2. The application

**Project → New Resource → Application → Public/Private Repository**,
pick the repository and branch, then:

| Setting | Value |
|---|---|
| Build Pack | **Dockerfile** |
| Base Directory | `/` (the Dockerfile copies `web/`, `cmd/`, `internal/` from the repo root) |
| Dockerfile Location | `/deploy/Dockerfile` |
| Ports Exposes | `8080` |
| Domain | `https://vault.example.com` — point its DNS at the Coolify host first |

**Environment Variables** (mark both as build-time *off*; they are
runtime-only):

| Variable | Value |
|---|---|
| `SECUREVAULT_MASTER_KEY` | output of `make genkey`, run locally. **Back it up outside Coolify** — losing it loses every stored file (see [operations.md](operations.md)). |
| `DATABASE_URL` | the internal URL copied in step 1 |

`ENV=prod`, `LISTEN_ADDR=0.0.0.0:8080` and `DATA_DIR=/data` are already
baked into the image; nothing else is required.

**Persistent Storage → Add → Volume Mount**, destination `/data`. Use a
named *volume* mount, not a host-directory bind: the image ships `/data`
owned by the distroless `nonroot` user (uid 65532) and a fresh named volume
inherits that ownership, whereas a bind-mounted host directory would be
root-owned and the nonroot process could not write to it.

**Healthcheck:** turn Coolify's built-in health check **off** for this
resource. It runs `curl`/`wget` *inside* the container, and the distroless
image deliberately has neither — with it on, Coolify would report the app
unhealthy forever and rolling deploys would never switch over. The proxy
still only routes to a running container.

**Deploy.** Coolify builds the image (frontend, then the Go binary with the
UI embedded), starts it, and the app applies migrations against the managed
Postgres on boot. Watch the deploy log for
`"msg":"migrations up to date"` followed by `"msg":"listening"`.

### 3. First admin

The first user to register is a normal user; promote an admin with the SQL
in [development.md](development.md) through the database resource's
terminal in Coolify (or `docker exec -it <pg-container> psql -U <user>
<database>` on the host).

### Security properties carried over

- Cookies are `Secure` and HSTS is emitted by the app (`ENV=prod` is set
  in the Dockerfile), so nothing depends on proxy configuration.
- No host ports are published; the app is reachable only through the
  proxy, the database only from the Coolify network.
- The blob-store volume and the Postgres data survive redeploys. Include
  both in backups (see [operations.md](operations.md)); Coolify can schedule
  Postgres backups on the database resource.
- If Coolify's "force HTTPS" redirect is available for the resource, turn
  it on; HSTS then makes it sticky for returning browsers.

### Alternative: one Compose resource

`docker-compose.coolify.yml` at the repository root bundles app + Postgres
into a single **Docker Compose** resource (Base Directory `/`, Docker
Compose Location `/docker-compose.coolify.yml`). Set
`SECUREVAULT_MASTER_KEY` under Environment Variables; Coolify fills
`SERVICE_PASSWORD_POSTGRES` and routes the domain you assign to the `app`
service via `SERVICE_FQDN_APP_8080`. Same image, same security properties —
use whichever fits how you manage the server.

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
