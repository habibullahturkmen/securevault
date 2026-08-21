package auth

// Registration-policy tests: bootstrap, closed mode, invite lifecycle
// (single use, expiry, revocation, normalization, admin gating), the user
// cap, and the audit trail of denials. Database-backed like service_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// bootstrapAdmin registers the first account (always admitted) and promotes
// it, mirroring how a deployment is set up.
func bootstrapAdmin(t *testing.T, s *Service) *User {
	t.Helper()
	ctx := context.Background()
	u, err := s.Register(ctx, uniqueName("root"), "root passphrase", "")
	if err != nil {
		t.Fatalf("bootstrap registration: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	u.Role = roleAdmin
	return u
}

func TestParseRegistrationMode(t *testing.T) {
	for in, want := range map[string]RegistrationMode{
		"": RegistrationOpen, "open": RegistrationOpen, " Invite ": RegistrationInvite, "CLOSED": RegistrationClosed,
	} {
		got, err := ParseRegistrationMode(in)
		if err != nil || got != want {
			t.Errorf("ParseRegistrationMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseRegistrationMode("public"); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestBootstrapIgnoresClosedMode(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	s.SetRegistrationPolicy(RegistrationPolicy{Mode: RegistrationClosed})

	st, err := s.RegistrationStatus(ctx)
	if err != nil || !st.Accepting || st.InviteRequired {
		t.Fatalf("empty system status = %+v, %v; want accepting without invite", st, err)
	}
	if _, err := s.Register(ctx, uniqueName("first"), "first passphrase", ""); err != nil {
		t.Fatalf("first account on an empty system must register even when closed: %v", err)
	}
	if _, err := s.Register(ctx, uniqueName("second"), "second passphrase", ""); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("second registration in closed mode: %v, want ErrRegistrationClosed", err)
	}
	st, _ = s.RegistrationStatus(ctx)
	if st.Accepting {
		t.Error("closed system reports accepting registrations")
	}
}

func TestInviteLifecycle(t *testing.T) {
	s, pool := testService(t)
	ctx := context.Background()
	admin := bootstrapAdmin(t, s)
	s.SetRegistrationPolicy(RegistrationPolicy{Mode: RegistrationInvite})

	st, _ := s.RegistrationStatus(ctx)
	if !st.Accepting || !st.InviteRequired {
		t.Fatalf("invite-mode status = %+v, want accepting with invite required", st)
	}

	// No code, wrong code.
	if _, err := s.Register(ctx, uniqueName("nocode"), "a valid passphrase", ""); !errors.Is(err, ErrInviteRequired) {
		t.Errorf("register without code: %v, want ErrInviteRequired", err)
	}
	if _, err := s.Register(ctx, uniqueName("badcode"), "a valid passphrase", "NOTAREALCODE"); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("register with bogus code: %v, want ErrInviteInvalid", err)
	}

	// Only admins issue codes; the plaintext is never stored.
	plain := &User{ID: admin.ID, Username: admin.Username, Role: roleUser}
	if _, _, err := s.CreateInvite(ctx, plain, "", 0); !errors.Is(err, ErrAdminRequired) {
		t.Errorf("non-admin CreateInvite: %v, want ErrAdminRequired", err)
	}
	code, inv, err := s.CreateInvite(ctx, admin, "for bob", 0)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status() != "active" || inv.CreatedBy != admin.Username || inv.Note != "for bob" {
		t.Errorf("fresh invite = %+v", inv)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE code_hash = $1`,
		HashToken(code)).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("invite hash lookup = %d, %v", stored, err)
	}
	var leaks int
	pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE note LIKE '%'||$1||'%'`, code).Scan(&leaks)
	if leaks != 0 {
		t.Error("plaintext invite code found in the database")
	}

	// Redeem with the code re-typed sloppily: lower case, spaces, a dash.
	sloppy := " " + string(code[:6]) + "-" + string(code[6:]) + " "
	sloppy = string([]byte(sloppy)) // copy
	bob, err := s.Register(ctx, uniqueName("bob"), "bobs passphrase", toLowerASCII(sloppy))
	if err != nil {
		t.Fatalf("register with valid code: %v", err)
	}
	// Single use.
	if _, err := s.Register(ctx, uniqueName("bob2"), "another passphrase", code); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("reusing a code: %v, want ErrInviteInvalid", err)
	}
	list, err := s.ListInvites(ctx, admin)
	if err != nil || len(list) != 1 || list[0].Status() != "used" || list[0].UsedBy != bob.Username {
		t.Errorf("ListInvites after redemption = %+v, %v", list, err)
	}
	// A used invite cannot be revoked.
	if err := s.RevokeInvite(ctx, admin, inv.ID); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("revoking a used invite: %v, want ErrInviteNotFound", err)
	}

	// Revoked codes are dead.
	code2, inv2, err := s.CreateInvite(ctx, admin, "revoked", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(ctx, admin, inv2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, uniqueName("late"), "late passphrase", code2); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("redeeming a revoked code: %v, want ErrInviteInvalid", err)
	}

	// Expired codes are dead.
	code3, inv3, err := s.CreateInvite(ctx, admin, "expired", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE invites SET expires_at = now() - interval '1 second' WHERE id = $1`, inv3.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, uniqueName("tardy"), "tardy passphrase", code3); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("redeeming an expired code: %v, want ErrInviteInvalid", err)
	}
	list, _ = s.ListInvites(ctx, admin)
	statuses := map[string]int{}
	for _, i := range list {
		statuses[i.Status()]++
	}
	if statuses["used"] != 1 || statuses["revoked"] != 1 || statuses["expired"] != 1 {
		t.Errorf("invite statuses = %v, want one each of used/revoked/expired", statuses)
	}

	// Policy edges on issuance.
	if _, _, err := s.CreateInvite(ctx, admin, "", 31*24*time.Hour); !errors.Is(err, ErrInvitePolicy) {
		t.Errorf("31-day invite: %v, want ErrInvitePolicy", err)
	}
	if _, _, err := s.CreateInvite(ctx, admin, string(make([]byte, 65)), 0); !errors.Is(err, ErrInvitePolicy) {
		t.Errorf("65-char note: %v, want ErrInvitePolicy", err)
	}
}

func TestMaxUsersEnforced(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	s.SetRegistrationPolicy(RegistrationPolicy{Mode: RegistrationOpen, MaxUsers: 2})

	for _, n := range []string{"one", "two"} {
		if _, err := s.Register(ctx, uniqueName(n), "a valid passphrase", ""); err != nil {
			t.Fatalf("register %s: %v", n, err)
		}
	}
	if _, err := s.Register(ctx, uniqueName("three"), "a valid passphrase", ""); !errors.Is(err, ErrUserLimitReached) {
		t.Errorf("third account with MaxUsers=2: %v, want ErrUserLimitReached", err)
	}
	st, _ := s.RegistrationStatus(ctx)
	if st.Accepting {
		t.Error("full system reports accepting registrations")
	}
}

func TestRegistrationDenialsAreAudited(t *testing.T) {
	s, pool := testService(t)
	ctx := context.Background()
	bootstrapAdmin(t, s)
	s.SetRegistrationPolicy(RegistrationPolicy{Mode: RegistrationInvite})

	name := uniqueName("mallory")
	s.Register(ctx, name, "a valid passphrase", "")
	s.Register(ctx, name, "a valid passphrase", "GUESSGUESSGUESS")

	reasons := map[string]int{}
	rows, err := pool.Query(ctx, `
		SELECT reason FROM audit_events
		WHERE action = 'auth.register' AND result = 'denied' AND target = $1`, name)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		rows.Scan(&r)
		reasons[r]++
	}
	if reasons["invite_required"] != 1 || reasons["invite_invalid"] != 1 {
		t.Errorf("audited denial reasons = %v, want invite_required and invite_invalid once each", reasons)
	}

	// The bootstrap registration is labelled as such.
	var bootstrap int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE action = 'auth.register' AND result = 'ok' AND reason = 'bootstrap'`).Scan(&bootstrap)
	if bootstrap != 1 {
		t.Errorf("bootstrap registrations audited = %d, want 1", bootstrap)
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
