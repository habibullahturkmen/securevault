// Package database owns the PostgreSQL connection pool and the embedded
// schema migration runner. Migrations are plain SQL files compiled into the
// binary; on startup they are applied in order, each inside its own
// transaction, guarded by an advisory lock so concurrent instances cannot
// race. Postgres DDL is transactional, so a failed migration leaves the
// schema untouched and the server refuses to start.
package database

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockID is an arbitrary but fixed key for pg_advisory_lock,
// scoping the lock to "SecureVault schema migrations".
const migrationLockID = 7245_3301

// Connect opens a pgx connection pool and verifies connectivity.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending embedded migrations in ascending order.
// It returns the number of migrations applied.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return 0, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrationLockID)

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version    integer PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("ensure schema_version table: %w", err)
	}

	var current int
	if err := conn.QueryRow(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return 0, err
	}

	applied := 0
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return applied, fmt.Errorf("migration %04d (%s): %w", m.version, m.name, err)
		}
		applied++
	}
	return applied, nil
}

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads embedded files named NNNN_description.sql and returns
// them sorted by version. Duplicate or malformed version numbers are startup
// errors, not warnings.
func loadMigrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	seen := make(map[int]string)
	var out []migration
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: expected NNNN_description.sql", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: invalid version prefix", name)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("duplicate migration version %d: %q and %q", v, prev, name)
		}
		seen[v] = name

		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, m migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_version (version) VALUES ($1)", m.version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
