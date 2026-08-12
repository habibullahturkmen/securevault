package authz

// Exhaustive authorization matrix: every principal class is exercised
// against every action, and the expected outcome is written out in full
// (proposal §7, "authorization matrix" scenario). Any change to the
// permission model must be made visible here.

import (
	"testing"

	"securevault/internal/auth"
)

var allActions = []Action{ActionView, ActionDownload, ActionRename, ActionDelete, ActionShare}

func TestAuthorizationMatrix(t *testing.T) {
	owner := &auth.User{ID: "owner-id", Username: "owner", Role: "user"}
	editor := &auth.User{ID: "editor-id", Username: "editor", Role: "user"}
	viewer := &auth.User{ID: "viewer-id", Username: "viewer", Role: "user"}
	unrelated := &auth.User{ID: "unrelated-id", Username: "unrelated", Role: "user"}
	admin := &auth.User{ID: "admin-id", Username: "admin", Role: "admin"}

	acl := NodeACL{
		OwnerID: owner.ID,
		Grants: map[string]string{
			editor.ID: RoleEditor,
			viewer.ID: RoleViewer,
		},
	}

	matrix := []struct {
		name string
		user *auth.User
		want map[Action]bool
	}{
		{"owner", owner, map[Action]bool{
			ActionView: true, ActionDownload: true, ActionRename: true,
			ActionDelete: true, ActionShare: true,
		}},
		{"editor", editor, map[Action]bool{
			ActionView: true, ActionDownload: true, ActionRename: true,
			ActionDelete: false, ActionShare: false,
		}},
		{"viewer", viewer, map[Action]bool{
			ActionView: true, ActionDownload: true, ActionRename: false,
			ActionDelete: false, ActionShare: false,
		}},
		{"unrelated user", unrelated, map[Action]bool{
			ActionView: false, ActionDownload: false, ActionRename: false,
			ActionDelete: false, ActionShare: false,
		}},
		// The admin ACCOUNT role conveys no file access through sharing
		// (proposal §4.3): identical to an unrelated user here.
		{"administrator", admin, map[Action]bool{
			ActionView: false, ActionDownload: false, ActionRename: false,
			ActionDelete: false, ActionShare: false,
		}},
		{"unauthenticated", nil, map[Action]bool{
			ActionView: false, ActionDownload: false, ActionRename: false,
			ActionDelete: false, ActionShare: false,
		}},
	}

	for _, row := range matrix {
		for _, action := range allActions {
			want, defined := row.want[action]
			if !defined {
				t.Fatalf("matrix row %q missing action %q", row.name, action)
			}
			if got := Can(row.user, acl, action); got != want {
				t.Errorf("Can(%s, %s) = %v, want %v", row.name, action, got, want)
			}
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	acl := NodeACL{OwnerID: "owner-id", Grants: map[string]string{"someone": RoleEditor}}

	// Unknown action falls through to deny — even for the owner.
	if Can(&auth.User{ID: "owner-id"}, acl, Action("administer")) {
		t.Error("undefined action allowed for owner")
	}
	// Corrupt/unknown grant role denies.
	badACL := NodeACL{OwnerID: "o", Grants: map[string]string{"u": "superuser"}}
	if Can(&auth.User{ID: "u"}, badACL, ActionView) {
		t.Error("unknown grant role allowed access")
	}
	// Empty user ID denies even if a grant somehow exists for "".
	weird := NodeACL{OwnerID: "o", Grants: map[string]string{"": RoleEditor}}
	if Can(&auth.User{ID: ""}, weird, ActionView) {
		t.Error("empty user ID allowed access")
	}
	// Nil grants map denies cleanly.
	if Can(&auth.User{ID: "u"}, NodeACL{OwnerID: "o"}, ActionView) {
		t.Error("nil grants map allowed access")
	}
}

func TestAdministrationCheck(t *testing.T) {
	if !CanAdministrate(&auth.User{ID: "a", Role: "admin"}) {
		t.Error("admin denied administration")
	}
	if CanAdministrate(&auth.User{ID: "u", Role: "user"}) {
		t.Error("regular user allowed administration")
	}
	if CanAdministrate(nil) {
		t.Error("nil user allowed administration")
	}
}
