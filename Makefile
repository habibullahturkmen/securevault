# SecureVault — development and CI entry points.
# `make check` runs the same gates as CI so nothing surprises you on push.

SHELL := /bin/bash
BIN   := bin/securevault

.PHONY: dev web-dev build test race check vet genkey db-create db-drop clean

## dev: run the API server locally (loads .env)
dev:
	set -a && source .env && set +a && go run ./cmd/server

## web-dev: run the Vite dev server with hot reload (proxies /api to :8080)
web-dev:
	cd web && pnpm dev

## build: production build — frontend first, then Go binary embedding web/dist
build:
	cd web && pnpm install --frozen-lockfile && pnpm build
	go build -tags embedui -o $(BIN) ./cmd/server

# Base test-database URL; packages append _auth / _api for isolation.
TEST_DB := postgres://securevault:securevault@localhost:5432/securevault_test

## test: full test suite (DB-backed tests skip if databases are absent)
test:
	TEST_DATABASE_URL=$(TEST_DB) go test ./...

## race: full test suite under the race detector (CI gate)
race:
	TEST_DATABASE_URL=$(TEST_DB) go test -race ./...

## vet: static analysis (CI gate)
vet:
	go vet ./...

## check: full local gate — mirrors .github/workflows/ci.yml
check: vet race
	@command -v gitleaks >/dev/null && gitleaks detect --no-banner || echo "gitleaks not installed — skipping (CI still runs it)"
	@command -v semgrep >/dev/null && semgrep scan --config auto --error || echo "semgrep not installed — skipping (CI still runs it)"
# .semgrepignore governs which paths both the line above and CI scan.

## genkey: generate a 32-byte hex master key for .env
genkey:
	@openssl rand -hex 32

## db-create: create the development and per-package test databases
db-create:
	@for db in securevault securevault_test_auth securevault_test_api; do \
		createdb $$db 2>/dev/null || true; \
		psql -d $$db -c "GRANT ALL ON SCHEMA public TO securevault;" >/dev/null; \
	done
	@echo "databases ready"

## db-drop: drop the development and test databases
db-drop:
	@for db in securevault securevault_test_auth securevault_test_api; do \
		dropdb --if-exists $$db; \
	done

clean:
	rm -rf bin web/dist
