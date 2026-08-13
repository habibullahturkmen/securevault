# SecureVault production image: multi-stage build producing a single static
# binary (API + storage engine + migrations + embedded web UI) on a
# distroless base — no shell, no package manager, nonroot user.

# Stage 1: build the web interface.
FROM node:22-alpine AS web
WORKDIR /src/web
ENV CI=true
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# Stage 2: build the Go binary with the UI embedded.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -tags embedui -trimpath -o /securevault ./cmd/server
# Skeleton for the blob-store volume, owned by distroless's nonroot user
# (uid 65532); a fresh named volume inherits this ownership on first mount.
RUN mkdir /data-skel

# Stage 3: minimal runtime.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /securevault /securevault
COPY --from=build --chown=65532:65532 /data-skel /data
# The encrypted blob store lives on this volume.
VOLUME ["/data"]
ENV DATA_DIR=/data LISTEN_ADDR=0.0.0.0:8080 ENV=prod
EXPOSE 8080
# The :nonroot base already defaults to uid 65532; stated explicitly so the
# no-root guarantee is visible in this file and checkable by scanners.
USER nonroot:nonroot
ENTRYPOINT ["/securevault"]
