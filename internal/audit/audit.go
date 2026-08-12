// Package audit records security-relevant events in an append-only table.
// Events carry actor, action, target, result, and reason — never passwords,
// keys, tokens, or file content. Audit failure must not fail the guarded
// operation, but it is always logged.
package audit

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Results for Event.Result.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Event is one audit record.
type Event struct {
	ActorID   string // user UUID; empty for unauthenticated actors
	ActorName string
	Action    string // e.g. "auth.login", "file.download", "share.grant"
	Target    string // e.g. node ID or username; never content
	Result    string // ok | denied | error
	Reason    string // short machine-readable reason code
	RequestID string
}

// Logger writes audit events to PostgreSQL.
type Logger struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Logger {
	return &Logger{pool: pool, log: log}
}

// Record inserts the event. Errors are logged, not returned: an audit
// insert failure must not turn a successful operation into a user-visible
// error, but it must never be silent either.
func (l *Logger) Record(ctx context.Context, e Event) {
	var actorID any
	if e.ActorID != "" {
		actorID = e.ActorID
	}
	_, err := l.pool.Exec(context.WithoutCancel(ctx), `
		INSERT INTO audit_events (actor_id, actor_name, action, target, result, reason, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		actorID, e.ActorName, e.Action, e.Target, e.Result, e.Reason, e.RequestID)
	if err != nil {
		l.log.Error("audit write failed",
			"action", e.Action, "result", e.Result, "err", err.Error())
	}
}
