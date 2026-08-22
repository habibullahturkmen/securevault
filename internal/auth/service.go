// Package auth implements SecureVault's from-scratch authentication:
// Argon2id password storage, opaque server-side sessions stored only as
// SHA-256 hashes, login throttling, uniform credential errors with timing
// equalization, and session rotation.
package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"securevault/internal/audit"
)

var (
	// ErrInvalidCredentials is returned for unknown usernames AND wrong
	// passwords — deliberately indistinguishable (uniform errors).
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrThrottled is returned when the failure threshold for the account
	// or client address has been reached.
	ErrThrottled = errors.New("too many failed attempts; try again later")
	// ErrUsernameTaken is returned on registration conflicts.
	ErrUsernameTaken = errors.New("username is already taken")
	// ErrSessionInvalid is returned for missing, unknown, or expired sessions.
	ErrSessionInvalid = errors.New("session is invalid or expired")
	// ErrPasswordPolicy is returned when a password violates the policy.
	ErrPasswordPolicy = errors.New("password must be between 8 and 128 characters")
	// ErrUsernamePolicy is returned when a username violates the policy.
	ErrUsernamePolicy = errors.New("username must be 3-32 characters: lowercase letters, digits, '_', '.', '-'")
)

// Password policy per NIST SP 800-63B: length is the only composition rule.
const (
	passwordMinLen = 8
	passwordMaxLen = 128
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)

// Throttling thresholds: sliding window over recorded failures.
const (
	throttleWindow      = 15 * time.Minute
	throttleUserMax     = 10 // failures per username in window
	throttleAddrMax     = 30 // failures per client address in window
	sessionIdleTTL      = 30 * time.Minute
	sessionAbsoluteTTL  = 4 * time.Hour
	roleUser, roleAdmin = "user", "admin"
)

// User is an authenticated principal.
type User struct {
	ID       string
	Username string
	Role     string
}

// IsAdmin reports whether the user holds the administrator account role.
func (u *User) IsAdmin() bool { return u.Role == roleAdmin }

// Service provides registration, login, session, and password operations.
type Service struct {
	pool               *pgxpool.Pool
	audit              *audit.Logger
	sessionIdleTTL     time.Duration
	sessionAbsoluteTTL time.Duration
	policy             RegistrationPolicy // see registration.go
}

func NewService(pool *pgxpool.Pool, auditLog *audit.Logger) *Service {
	return &Service{pool: pool, audit: auditLog,
		sessionIdleTTL: sessionIdleTTL, sessionAbsoluteTTL: sessionAbsoluteTTL,
		policy: RegistrationPolicy{Mode: RegistrationOpen}}
}

// Register creates a new account with the default user role, subject to the
// registration policy (mode, invite code, user cap — see registration.go).
// inviteCode is ignored unless the policy requires one.
func (s *Service) Register(ctx context.Context, username, password, inviteCode string) (*User, error) {
	if !usernameRe.MatchString(username) {
		return nil, ErrUsernamePolicy
	}
	if len(password) < passwordMinLen || len(password) > passwordMaxLen {
		return nil, ErrPasswordPolicy
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Policy check, insert, and invite consumption are one transaction so a
	// code can never be spent without the account existing, or vice versa.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: begin registration: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	reason, inviteID, err := s.admitRegistration(ctx, tx, username, inviteCode)
	if err != nil {
		return nil, err
	}

	u := &User{Username: username, Role: roleUser}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (username, password_hash) VALUES ($1, $2)
		RETURNING id`, username, hash).Scan(&u.ID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("auth: create user: %w", err)
	}
	if inviteID != "" {
		if _, err := tx.Exec(ctx, `
			UPDATE invites SET used_by = $1, used_at = now() WHERE id = $2`,
			u.ID, inviteID); err != nil {
			return nil, fmt.Errorf("auth: consume invite: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit registration: %w", err)
	}

	s.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: username,
		Action: "auth.register", Target: username, Result: audit.ResultOK, Reason: reason,
	})
	if inviteID != "" {
		s.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: username,
			Action: "invite.redeem", Target: inviteID, Result: audit.ResultOK,
		})
	}
	return u, nil
}

// Login verifies credentials and returns a fresh session token. Every
// failure path costs one Argon2id verification (timing equalization) and
// returns the same ErrInvalidCredentials. clientAddr is the network origin
// used for address-based throttling.
func (s *Service) Login(ctx context.Context, username, password, clientAddr string) (string, *User, error) {
	userKey, addrKey := "u:"+username, "ip:"+clientAddr

	throttled, err := s.isThrottled(ctx, userKey, addrKey)
	if err != nil {
		return "", nil, err
	}
	if throttled {
		s.audit.Record(ctx, audit.Event{
			ActorName: username, Action: "auth.login", Target: username,
			Result: audit.ResultDenied, Reason: "throttled",
		})
		return "", nil, ErrThrottled
	}

	u := &User{Username: username}
	var passwordHash string
	err = s.pool.QueryRow(ctx, `
		SELECT id, role, password_hash FROM users WHERE username = $1`,
		username).Scan(&u.ID, &u.Role, &passwordHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		EqualizeTiming(password) // unknown account costs the same as a real check
		return "", nil, s.loginFailed(ctx, username, userKey, addrKey, "unknown_user")
	case err != nil:
		return "", nil, fmt.Errorf("auth: look up user: %w", err)
	}

	ok, err := VerifyPassword(password, passwordHash)
	if err != nil {
		return "", nil, fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		return "", nil, s.loginFailed(ctx, username, userKey, addrKey, "wrong_password")
	}

	// Success: clear the account's failure window and issue a fresh token
	// (session rotation — a new identifier on every authentication).
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM login_failures WHERE key = $1`, userKey); err != nil {
		return "", nil, fmt.Errorf("auth: clear failures: %w", err)
	}
	token, err := s.createSession(ctx, u.ID)
	if err != nil {
		return "", nil, err
	}

	s.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: username,
		Action: "auth.login", Target: username, Result: audit.ResultOK,
	})
	return token, u, nil
}

func (s *Service) loginFailed(ctx context.Context, username, userKey, addrKey, reason string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO login_failures (key) VALUES ($1), ($2)`, userKey, addrKey); err != nil {
		return fmt.Errorf("auth: record failure: %w", err)
	}
	s.audit.Record(ctx, audit.Event{
		ActorName: username, Action: "auth.login", Target: username,
		Result: audit.ResultDenied, Reason: reason,
	})
	return ErrInvalidCredentials
}

func (s *Service) isThrottled(ctx context.Context, userKey, addrKey string) (bool, error) {
	// Opportunistic pruning keeps the table small without a background job.
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM login_failures WHERE attempted_at < now() - $1::interval`,
		throttleWindow.String()); err != nil {
		return false, fmt.Errorf("auth: prune failures: %w", err)
	}

	var userFails, addrFails int
	err := s.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE key = $1),
			count(*) FILTER (WHERE key = $2)
		FROM login_failures
		WHERE key IN ($1, $2) AND attempted_at >= now() - $3::interval`,
		userKey, addrKey, throttleWindow.String()).Scan(&userFails, &addrFails)
	if err != nil {
		return false, fmt.Errorf("auth: count failures: %w", err)
	}
	return userFails >= throttleUserMax || addrFails >= throttleAddrMax, nil
}

func (s *Service) createSession(ctx context.Context, userID string) (string, error) {
	token, hash, err := NewSessionToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, now() + $3::interval)`,
		userID, hash, s.sessionAbsoluteTTL.String()); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	return token, nil
}

// ValidateSession resolves a client token to its user. It enforces both the
// absolute lifetime and the inactivity timeout, then records this request as
// activity without extending the absolute deadline.
func (s *Service) ValidateSession(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, ErrSessionInvalid
	}
	u := &User{}
	err := s.pool.QueryRow(ctx, `
		UPDATE sessions AS s SET last_seen_at = now()
		FROM users u
		WHERE s.user_id = u.id
		  AND s.token_hash = $1
		  AND s.expires_at > now()
		  AND s.last_seen_at > now() - $2::interval
		RETURNING u.id, u.username, u.role`,
		HashToken(token), s.sessionIdleTTL.String()).Scan(&u.ID, &u.Username, &u.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("auth: validate session: %w", err)
	}
	return u, nil
}

// Logout invalidates the presented session token.
func (s *Service) Logout(ctx context.Context, token string, u *User) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE token_hash = $1`, HashToken(token)); err != nil {
		return fmt.Errorf("auth: destroy session: %w", err)
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username,
		Action: "auth.logout", Target: u.Username, Result: audit.ResultOK,
	})
	return nil
}

// ChangePassword verifies the current password, stores the new hash, and
// destroys every session for the user. The returned token is a fresh
// session so the current client stays signed in on a rotated identifier.
func (s *Service) ChangePassword(ctx context.Context, u *User, current, next string) (string, error) {
	if len(next) < passwordMinLen || len(next) > passwordMaxLen {
		return "", ErrPasswordPolicy
	}

	var passwordHash string
	if err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&passwordHash); err != nil {
		return "", fmt.Errorf("auth: look up user: %w", err)
	}
	ok, err := VerifyPassword(current, passwordHash)
	if err != nil {
		return "", err
	}
	if !ok {
		s.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: u.Username,
			Action: "auth.password_change", Target: u.Username,
			Result: audit.ResultDenied, Reason: "wrong_password",
		})
		return "", ErrInvalidCredentials
	}

	newHash, err := HashPassword(next)
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE users SET password_hash = $1, password_changed_at = now()
		WHERE id = $2`, newHash, u.ID); err != nil {
		return "", fmt.Errorf("auth: update password: %w", err)
	}
	// Revoke every existing session, then issue a fresh one.
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1`, u.ID); err != nil {
		return "", fmt.Errorf("auth: revoke sessions: %w", err)
	}
	token, err := s.createSession(ctx, u.ID)
	if err != nil {
		return "", err
	}

	s.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username,
		Action: "auth.password_change", Target: u.Username, Result: audit.ResultOK,
	})
	return token, nil
}
