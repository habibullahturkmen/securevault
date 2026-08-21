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
a native **Railpack** application (Coolify's default build pack) — Coolify
builds the frontend, then the Go binary with it embedded, straight from the
repository according to `railpack.json` — and PostgreSQL as a
Coolify-managed database resource next to it. No Dockerfile or Compose file
is involved. Both land on the same Docker network, which is the "internal"
zone of the Compose stack above.

`railpack.json` at the repository root drives the build: Railpack's Go
provider detects `go.mod` and brings Go 1.25 (via mise); `packages` adds
Node 22; the overridden `build` step runs `pnpm install` and `pnpm build`
in `web/` (pnpm fetched at the version pinned in `package.json`) and then
`go build -tags embedui` so `web/dist` is embedded; the runtime image
(Debian slim + curl/wget) starts `./out`. Commands in `railpack.json` are
run through `sh -c '…'`, so avoid double quotes inside them.
`LISTEN_ADDR=0.0.0.0:8080`, `DATA_DIR=/data` and `ENV=prod` are set as
deploy variables there — the secrets are not.

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
| Build Pack | **Railpack** (the default) |
| Base Directory | `/` — `railpack.json`, `go.mod` and `web/` are all at the root |
| Install / Build / Start Command | leave **empty**; `railpack.json` defines them |
| Ports Exposes | `8080` |
| Domain | `https://vault.example.com` — point its DNS at the Coolify host first |

**Environment Variables** (mark both as build-time *off*; they are
runtime-only):

| Variable | Value |
|---|---|
| `SECUREVAULT_MASTER_KEY` | output of `make genkey`, run locally. **Back it up outside Coolify** — losing it loses every stored file (see [operations.md](operations.md)). |
| `DATABASE_URL` | the internal URL copied in step 1 |

Nothing else is required: `ENV=prod`, `LISTEN_ADDR=0.0.0.0:8080` and
`DATA_DIR=/data` come from `railpack.json`.

**Persistent Storage → Add → Volume Mount**, destination `/data`. The
blob store lives there; the app creates its subdirectories on first start.
(The Railpack runtime image runs as root, so a host-directory bind also
works, but a named volume is the simpler choice.)

**Healthcheck** tab — enable it with:

| Field | Value |
|---|---|
| Method / Scheme | `GET` / `http` |
| Host / Port | `localhost` / `8080` |
| Path | `/api/health` |
| Return code | `200` |
| Interval / Timeout / Retries / Start period | `30` / `5` / `3` / `10` seconds |

Coolify runs this check with `curl` (or `wget`) *inside* the container;
with Railpack it installs both into the runtime image itself
(`RAILPACK_DEPLOY_APT_PACKAGES=curl wget` in the build log), so nothing
extra is needed.

**Deploy.** Watch the build log: the Railpack plan it prints should show
the `build` step with the `pnpm` commands and `go build -tags embedui`,
and `deploy.variables` with `LISTEN_ADDR`. On start the app applies
migrations against the managed Postgres; the runtime log must read

```
"msg":"listening","addr":"0.0.0.0:8080","dev":false,"embedded_ui":true
```

`127.0.0.1:8080` / `"dev":true` / `"embedded_ui":false` means the build
ran without `railpack.json` (wrong branch or Base Directory).

### 3. First admin

The first user to register is a normal user; promote an admin with the SQL
in [development.md](development.md) through the database resource's
terminal in Coolify (or `docker exec -it <pg-container> psql -U <user>
<database>` on the host).

### Security properties carried over

- Cookies are `Secure` and HSTS is emitted by the app (`ENV=prod` is set
  in `railpack.json`), so nothing depends on proxy configuration.
- No host ports are published; the app is reachable only through the
  proxy, the database only from the Coolify network.
- The blob-store volume and the Postgres data survive redeploys. Include
  both in backups (see [operations.md](operations.md)); Coolify can schedule
  Postgres backups on the database resource.
- If Coolify's "force HTTPS" redirect is available for the resource, turn
  it on; HSTS then makes it sticky for returning browsers.

### Alternatives

Same binary, same security properties — pick whichever fits how you manage
the server:

- **Nixpacks build pack** (older Coolify default, still selectable).
  `nixpacks.toml` at the repository root is the equivalent of
  `railpack.json`: Node added to the Go provider, a `web` phase for the
  frontend, `go build -tags embedui`, the same variables, and a run image
  that ships curl so Coolify's health check works.
- **Dockerfile application.** Build Pack *Dockerfile*, Base Directory `/`,
  Dockerfile Location `/deploy/Dockerfile`, port `8080`, the same two
  environment variables and `/data` volume. Differences from Nixpacks: the
  image is distroless and runs as the `nonroot` user, so use a named
  *volume* mount (not a host-directory bind, which would be root-owned) and
  turn Coolify's health check off (no `curl`/`wget` in the image).
- **One Compose resource.** `docker-compose.coolify.yml` at the repository
  root bundles app + Postgres (Base Directory `/`, Docker Compose Location
  `/docker-compose.coolify.yml`). Set `SECUREVAULT_MASTER_KEY` under
  Environment Variables; Coolify fills `SERVICE_PASSWORD_POSTGRES` and
  routes the domain you assign to the `app` service via
  `SERVICE_FQDN_APP_8080`.

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
