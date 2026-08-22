package auth

// Adversarial authentication tests (proposal §7): uniform errors, throttling,
// session lifecycle, rotation, and expiry. These need PostgreSQL; they skip
// unless TEST_DATABASE_URL is set. CI and `make race` provide it.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"securevault/internal/audit"
	"securevault/internal/database"
)

var userSeq atomic.Int64

func testService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database-backed auth tests")
	}
	// Package-private database: go test runs packages concurrently, and
	// each package's setup truncates tables. Sharing one database would
	// let another package wipe this one's state mid-test.
	url += "_auth"
	ctx := context.Background()
	pool, err := database.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	if _, err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Isolate from prior runs; each test also uses unique usernames.
	if _, err := pool.Exec(ctx,
		"TRUNCATE users, sessions, login_failures, invites, audit_events CASCADE"); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewService(pool, audit.New(pool, log)), pool
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, userSeq.Add(1))
}

func TestRegisterLoginLogoutLifecycle(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	name := uniqueName("alice")

	u, err := s.Register(ctx, name, "a strong passphrase", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "user" {
		t.Errorf("new account role = %q, want user", u.Role)
	}

	token, lu, err := s.Login(ctx, name, "a strong passphrase", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if lu.ID != u.ID {
		t.Error("login resolved a different user")
	}

	got, err := s.ValidateSession(ctx, token)
	if err != nil || got.ID != u.ID {
		t.Fatalf("session invalid immediately after login: %v", err)
	}

	if err := s.Logout(ctx, token, lu); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("token valid after logout: err = %v", err)
	}
}

// TestUniformCredentialErrors: unknown username and wrong password must be
// indistinguishable to the client.
func TestUniformCredentialErrors(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	name := uniqueName("bob")

	if _, err := s.Register(ctx, name, "bobs real password", ""); err != nil {
		t.Fatal(err)
	}

	_, _, errUnknown := s.Login(ctx, uniqueName("ghost"), "whatever", "203.0.113.8")
	_, _, errWrong := s.Login(ctx, name, "not bobs password", "203.0.113.8")

	if !errors.Is(errUnknown, ErrInvalidCredentials) {
		t.Errorf("unknown user: %v, want ErrInvalidCredentials", errUnknown)
	}
	if !errors.Is(errWrong, ErrInvalidCredentials) {
		t.Errorf("wrong password: %v, want ErrInvalidCredentials", errWrong)
	}
	if errUnknown.Error() != errWrong.Error() {
		t.Error("error messages differ between unknown user and wrong password")
	}
}

func TestThrottlingAfterRepeatedFailures(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	name := uniqueName("carol")

	if _, err := s.Register(ctx, name, "carols password", ""); err != nil {
		t.Fatal(err)
	}

	// Distinct client addresses so only the per-username threshold trips.
	for i := 0; i < throttleUserMax; i++ {
		addr := fmt.Sprintf("198.51.100.%d", i)
		if _, _, err := s.Login(ctx, name, "wrong", addr); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}

	// Next attempt — even with the CORRECT password — is throttled.
	_, _, err := s.Login(ctx, name, "carols password", "198.51.100.200")
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("after %d failures: %v, want ErrThrottled", throttleUserMax, err)
	}
}

func TestAddressThrottling(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	addr := "192.0.2.66"

	// One address spraying many usernames trips the per-address threshold.
	for i := 0; i < throttleAddrMax; i++ {
		s.Login(ctx, uniqueName("spray"), "wrong", addr)
	}
	_, _, err := s.Login(ctx, uniqueName("spray"), "wrong", addr)
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("after %d failures from one address: %v, want ErrThrottled", throttleAddrMax, err)
	}
}

func TestSessionRotationOnLogin(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	name := uniqueName("dave")

	if _, err := s.Register(ctx, name, "daves password", ""); err != nil {
		t.Fatal(err)
	}
	t1, _, err := s.Login(ctx, name, "daves password", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	t2, _, err := s.Login(ctx, name, "daves password", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Error("two logins produced the same session token")
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	name := uniqueName("erin")

	if _, err := s.Register(ctx, name, "erins old password", ""); err != nil {
		t.Fatal(err)
	}
	oldToken, u, err := s.Login(ctx, name, "erins old password", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := s.Login(ctx, name, "erins old password", "203.0.113.11")
	if err != nil {
		t.Fatal(err)
	}

	// Wrong current password is rejected and audited.
	if _, err := s.ChangePassword(ctx, u, "not the old password", "erins new password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong current password: %v, want ErrInvalidCredentials", err)
	}

	newToken, err := s.ChangePassword(ctx, u, "erins old password", "erins new password")
	if err != nil {
		t.Fatal(err)
	}

	// Every pre-change session is dead; the rotated token works.
	for _, tok := range []string{oldToken, otherToken} {
		if _, err := s.ValidateSession(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
			t.Errorf("pre-change session still valid after password change")
		}
	}
	if _, err := s.ValidateSession(ctx, newToken); err != nil {
		t.Errorf("rotated session invalid: %v", err)
	}

	// Old password no longer authenticates; new one does.
	if _, _, err := s.Login(ctx, name, "erins old password", "203.0.113.12"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("old password still accepted: %v", err)
	}
	if _, _, err := s.Login(ctx, name, "erins new password", "203.0.113.12"); err != nil {
		t.Errorf("new password rejected: %v", err)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s, pool := testService(t)
	ctx := context.Background()
	name := uniqueName("frank")

	if _, err := s.Register(ctx, name, "franks password", ""); err != nil {
		t.Fatal(err)
	}
	token, u, err := s.Login(ctx, name, "franks password", "203.0.113.13")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE sessions SET expires_at = now() - interval '1 minute'
		WHERE user_id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("expired session accepted: err = %v", err)
	}
}

func TestIdleSessionRejected(t *testing.T) {
	s, pool := testService(t)
	ctx := context.Background()
	name := uniqueName("idle")
	credential := name + " passphrase"

	if _, err := s.Register(ctx, name, credential, ""); err != nil {
		t.Fatal(err)
	}
	token, u, err := s.Login(ctx, name, credential, "203.0.113.14")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE sessions SET last_seen_at = now() - interval '31 minutes'
		WHERE user_id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("idle session accepted: err = %v", err)
	}
}

func TestRegistrationPolicy(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()

	bad := []struct{ username, password string }{
		{"ab", "long enough password"},            // username too short
		{"UPPER", "long enough password"},         // uppercase rejected
		{"has space", "long enough password"},     // space rejected
		{"../etc/passwd", "long enough password"}, // traversal characters
		{uniqueName("ok"), "short"},               // password too short
	}
	for _, c := range bad {
		if _, err := s.Register(ctx, c.username, c.password, ""); err == nil {
			t.Errorf("Register(%q, %q) succeeded, want policy error", c.username, c.password)
		}
	}

	name := uniqueName("grace")
	if _, err := s.Register(ctx, name, "graces password", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, name, "another password", ""); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate username: %v, want ErrUsernameTaken", err)
	}
}

func TestAuditTrailForAuthEvents(t *testing.T) {
	s, pool := testService(t)
	ctx := context.Background()
	name := uniqueName("henry")

	s.Register(ctx, name, "henrys password", "")
	s.Login(ctx, name, "wrong password", "203.0.113.14")
	s.Login(ctx, name, "henrys password", "203.0.113.14")

	var denied, ok int
	if err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE result = 'denied'),
			count(*) FILTER (WHERE result = 'ok')
		FROM audit_events WHERE action = 'auth.login' AND target = $1`,
		name).Scan(&denied, &ok); err != nil {
		t.Fatal(err)
	}
	if denied != 1 || ok != 1 {
		t.Errorf("audit login events: denied=%d ok=%d, want 1 and 1", denied, ok)
	}

	// The audit table must never contain the password.
	var leaks int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE reason LIKE '%henrys password%' OR target LIKE '%henrys password%'`).
		Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if leaks != 0 {
		t.Error("password text found in audit_events")
	}
}
