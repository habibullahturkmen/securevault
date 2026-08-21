package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"securevault/internal/audit"
)

// RegistrationMode decides who may create an account.
type RegistrationMode string

const (
	// RegistrationOpen lets anyone register (development default).
	RegistrationOpen RegistrationMode = "open"
	// RegistrationInvite requires a one-time code issued by an administrator.
	RegistrationInvite RegistrationMode = "invite"
	// RegistrationClosed refuses every registration.
	RegistrationClosed RegistrationMode = "closed"
)

// ParseRegistrationMode validates a configuration value; anything outside
// the three known modes is a startup error (fail closed).
func ParseRegistrationMode(s string) (RegistrationMode, error) {
	switch m := RegistrationMode(strings.ToLower(strings.TrimSpace(s))); m {
	case RegistrationOpen, RegistrationInvite, RegistrationClosed:
		return m, nil
	case "":
		return RegistrationOpen, nil
	default:
		return "", fmt.Errorf("unknown registration mode %q (open, invite, or closed)", s)
	}
}

// RegistrationPolicy is the account-creation policy the service enforces.
// Whatever the mode, the very first account on an empty system may always
// register (bootstrap) so a fresh deployment cannot lock itself out; that
// account is then promoted to admin through system configuration.
type RegistrationPolicy struct {
	Mode RegistrationMode
	// MaxUsers caps the total number of accounts; 0 means unlimited.
	MaxUsers int64
}

var (
	// ErrRegistrationClosed is returned in closed mode (after bootstrap).
	ErrRegistrationClosed = errors.New("registration is closed")
	// ErrInviteRequired is returned in invite mode when no code was given.
	ErrInviteRequired = errors.New("an invite code is required to register")
	// ErrInviteInvalid covers unknown, expired, revoked, and already-used
	// codes — deliberately indistinguishable.
	ErrInviteInvalid = errors.New("invite code is invalid, expired, or already used")
	// ErrUserLimitReached is returned once MaxUsers accounts exist.
	ErrUserLimitReached = errors.New("the account limit has been reached")
	// ErrInviteNotFound is returned when revoking an unknown or inactive invite.
	ErrInviteNotFound = errors.New("invite not found")
	// ErrInvitePolicy is returned for an out-of-range lifetime or note.
	ErrInvitePolicy = errors.New("invite lifetime must be 1 minute to 30 days and the note at most 64 characters")
	// ErrAdminRequired is returned when a non-admin calls an admin operation.
	ErrAdminRequired = errors.New("administrator role required")
)

const (
	// registrationLockID serializes registrations so the bootstrap rule and
	// MaxUsers hold under concurrent requests (pg_advisory_xact_lock).
	registrationLockID = 7245_3302

	inviteCodeBytes   = 16 // 128 bits of entropy
	inviteDefaultTTL  = 7 * 24 * time.Hour
	inviteMinTTL      = time.Minute
	inviteMaxTTL      = 30 * 24 * time.Hour
	inviteNoteMaxLen  = 64
	inviteListMaxRows = 200
)

// Codes are base32 (A–Z, 2–7): case-insensitive and free of look-alike
// characters, so they can be read out loud or typed from a note.
var inviteEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// SetRegistrationPolicy installs the policy; the default is open.
func (s *Service) SetRegistrationPolicy(p RegistrationPolicy) {
	if p.Mode == "" {
		p.Mode = RegistrationOpen
	}
	s.policy = p
}

// RegistrationStatus is what an anonymous client may learn about the policy:
// enough for the sign-up form to show the right fields, nothing more.
type RegistrationStatus struct {
	Mode           RegistrationMode
	Accepting      bool // any registration currently possible
	InviteRequired bool // registration needs a code
}

// RegistrationStatus reports the effective policy, taking bootstrap and the
// user cap into account.
func (s *Service) RegistrationStatus(ctx context.Context) (RegistrationStatus, error) {
	var count int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return RegistrationStatus{}, fmt.Errorf("auth: count users: %w", err)
	}
	st := RegistrationStatus{Mode: s.policy.Mode}
	switch {
	case count == 0:
		st.Accepting = true // bootstrap
	case s.policy.MaxUsers > 0 && count >= s.policy.MaxUsers:
		st.Accepting = false
	case s.policy.Mode == RegistrationClosed:
		st.Accepting = false
	default:
		st.Accepting = true
		st.InviteRequired = s.policy.Mode == RegistrationInvite
	}
	return st, nil
}

// Invite is an issued invite code as seen by administrators. The code
// itself is never stored or listed.
type Invite struct {
	ID        string
	Note      string
	CreatedBy string // username of the issuing admin
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    string // username of the redeemer, or ""
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// Status summarizes an invite's lifecycle: active, used, revoked, or expired.
func (i Invite) Status() string {
	switch {
	case i.UsedAt != nil:
		return "used"
	case i.RevokedAt != nil:
		return "revoked"
	case time.Now().After(i.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

// CreateInvite issues a one-time code valid for ttl (default 7 days). The
// plaintext code is returned exactly once; only its hash is stored.
func (s *Service) CreateInvite(ctx context.Context, admin *User, note string, ttl time.Duration) (string, *Invite, error) {
	if admin == nil || !admin.IsAdmin() {
		return "", nil, ErrAdminRequired
	}
	if ttl == 0 {
		ttl = inviteDefaultTTL
	}
	note = strings.TrimSpace(note)
	if ttl < inviteMinTTL || ttl > inviteMaxTTL || len(note) > inviteNoteMaxLen {
		return "", nil, ErrInvitePolicy
	}

	raw := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: generate invite code: %w", err)
	}
	code := inviteEncoding.EncodeToString(raw)

	inv := &Invite{Note: note, CreatedBy: admin.Username}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO invites (code_hash, note, created_by, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)
		RETURNING id, created_at, expires_at`,
		HashToken(code), note, admin.ID, ttl.String()).
		Scan(&inv.ID, &inv.CreatedAt, &inv.ExpiresAt)
	if err != nil {
		return "", nil, fmt.Errorf("auth: create invite: %w", err)
	}

	s.audit.Record(ctx, audit.Event{
		ActorID: admin.ID, ActorName: admin.Username,
		Action: "invite.create", Target: inv.ID, Result: audit.ResultOK,
	})
	return code, inv, nil
}

// ListInvites returns the most recent invites, newest first.
func (s *Service) ListInvites(ctx context.Context, admin *User) ([]Invite, error) {
	if admin == nil || !admin.IsAdmin() {
		return nil, ErrAdminRequired
	}
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.note, c.username, i.created_at, i.expires_at,
		       COALESCE(u.username, ''), i.used_at, i.revoked_at
		FROM invites i
		JOIN users c ON c.id = i.created_by
		LEFT JOIN users u ON u.id = i.used_by
		ORDER BY i.created_at DESC
		LIMIT $1`, inviteListMaxRows)
	if err != nil {
		return nil, fmt.Errorf("auth: list invites: %w", err)
	}
	defer rows.Close()

	out := []Invite{}
	for rows.Next() {
		var i Invite
		if err := rows.Scan(&i.ID, &i.Note, &i.CreatedBy, &i.CreatedAt, &i.ExpiresAt,
			&i.UsedBy, &i.UsedAt, &i.RevokedAt); err != nil {
			return nil, fmt.Errorf("auth: scan invite: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// RevokeInvite cancels an active invite. Used or already-revoked invites
// cannot be revoked again; that is ErrInviteNotFound.
func (s *Service) RevokeInvite(ctx context.Context, admin *User, id string) error {
	if admin == nil || !admin.IsAdmin() {
		return ErrAdminRequired
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE invites SET revoked_at = now()
		WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("auth: revoke invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: admin.ID, ActorName: admin.Username,
		Action: "invite.revoke", Target: id, Result: audit.ResultOK,
	})
	return nil
}

// normalizeInviteCode accepts the code however a human re-types it:
// any case, with spaces or dashes.
func normalizeInviteCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	return strings.NewReplacer(" ", "", "-", "").Replace(code)
}

// admitRegistration applies the policy inside the registration transaction.
// It returns the audit reason for a successful registration and, in invite
// mode, the id of the invite to consume. Denials are audited here.
func (s *Service) admitRegistration(ctx context.Context, tx pgx.Tx, username, inviteCode string) (reason, inviteID string, err error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, registrationLockID); err != nil {
		return "", "", fmt.Errorf("auth: lock registrations: %w", err)
	}
	var count int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return "", "", fmt.Errorf("auth: count users: %w", err)
	}
	if count == 0 {
		return "bootstrap", "", nil
	}

	deny := func(code string, err error) (string, string, error) {
		s.audit.Record(ctx, audit.Event{
			ActorName: username, Action: "auth.register", Target: username,
			Result: audit.ResultDenied, Reason: code,
		})
		return "", "", err
	}

	if s.policy.MaxUsers > 0 && count >= s.policy.MaxUsers {
		return deny("user_limit", ErrUserLimitReached)
	}
	switch s.policy.Mode {
	case RegistrationClosed:
		return deny("registration_closed", ErrRegistrationClosed)
	case RegistrationInvite:
		code := normalizeInviteCode(inviteCode)
		if code == "" {
			return deny("invite_required", ErrInviteRequired)
		}
		// FOR UPDATE: two concurrent redemptions of one code serialize here
		// and the second sees used_at set.
		err := tx.QueryRow(ctx, `
			SELECT id FROM invites
			WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL
			  AND expires_at > now()
			FOR UPDATE`, HashToken(code)).Scan(&inviteID)
		if errors.Is(err, pgx.ErrNoRows) {
			return deny("invite_invalid", ErrInviteInvalid)
		}
		if err != nil {
			return "", "", fmt.Errorf("auth: look up invite: %w", err)
		}
		return "invite", inviteID, nil
	default:
		return "open", "", nil
	}
}
