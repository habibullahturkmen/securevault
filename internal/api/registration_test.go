package api

// Registration policy over real HTTP: the public status endpoint, closed
// mode, and the full invite flow through the admin endpoints (issue, redeem,
// single use, revoke, non-admin denial, CSRF).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"securevault/internal/auth"
)

type registrationStatus struct {
	Mode                   string `json:"mode"`
	AcceptingRegistrations bool   `json:"acceptingRegistrations"`
	InviteRequired         bool   `json:"inviteRequired"`
}

func (c *client) registrationStatus() registrationStatus {
	var st registrationStatus
	json.Unmarshal(c.req("GET", "/api/auth/registration", nil, "", http.StatusOK), &st)
	return st
}

func TestRegistrationClosed(t *testing.T) {
	e := newEnvWithPolicy(t, auth.RegistrationPolicy{Mode: auth.RegistrationClosed})
	anon := e.anon()

	if st := anon.registrationStatus(); st.Mode != "closed" || !st.AcceptingRegistrations {
		t.Fatalf("empty closed system status = %+v; want accepting (bootstrap)", st)
	}
	// Bootstrap account is admitted; everyone after is refused with 403.
	e.registerAndLogin(uniqueUser("root"))
	anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": uniqueUser("late"), "password": "a valid passphrase"},
		http.StatusForbidden)
	if st := anon.registrationStatus(); st.AcceptingRegistrations {
		t.Errorf("closed system status = %+v; want not accepting", st)
	}
}

func TestInviteFlowOverHTTP(t *testing.T) {
	e := newEnvWithPolicy(t, auth.RegistrationPolicy{Mode: auth.RegistrationInvite})
	rootName := uniqueUser("root")
	root := e.registerAndLogin(rootName) // bootstrap
	anon := e.anon()

	if st := anon.registrationStatus(); !st.AcceptingRegistrations || !st.InviteRequired {
		t.Fatalf("invite-mode status = %+v", st)
	}
	// Without a code: 403, and the service says so.
	body := anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": uniqueUser("bob"), "password": "bobs passphrase"},
		http.StatusForbidden)
	if !strings.Contains(string(body), "invite code is required") {
		t.Errorf("no-code error body = %s", body)
	}

	// A plain user cannot see or mint invites (404, like every admin surface).
	if code := root.statusOf("GET", "/api/admin/invites", nil, ""); code != http.StatusNotFound {
		t.Errorf("non-admin GET invites = %d, want 404", code)
	}
	root.jsonReq("POST", "/api/admin/invites", map[string]any{"note": "x"}, http.StatusNotFound)

	e.promoteToAdmin(rootName)
	// Sessions resolve the role on every request, so no re-login is needed.
	var created struct {
		Code   string         `json:"code"`
		Invite map[string]any `json:"invite"`
	}
	json.Unmarshal(root.jsonReq("POST", "/api/admin/invites",
		map[string]any{"note": "for bob", "ttlHours": 24}, http.StatusCreated), &created)
	if len(created.Code) < 20 || created.Invite["status"] != "active" {
		t.Fatalf("create invite response = %+v", created)
	}
	inviteID := created.Invite["id"].(string)

	// Missing CSRF token on the state-changing admin call.
	req, _ := http.NewRequest("POST", root.base+"/api/admin/invites", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := root.http.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST invites without CSRF header: %v / %v, want 403", resp.StatusCode, err)
	}

	// Bad code 403; good code 201; reuse 403.
	bobName := uniqueUser("bob")
	anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": bobName, "password": "bobs passphrase", "inviteCode": "WRONGWRONGWRONG"},
		http.StatusForbidden)
	anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": bobName, "password": "bobs passphrase", "inviteCode": created.Code},
		http.StatusCreated)
	anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": uniqueUser("eve"), "password": "eves passphrase", "inviteCode": created.Code},
		http.StatusForbidden)

	// The list shows it used by bob and never contains the code.
	listBody := root.req("GET", "/api/admin/invites", nil, "", http.StatusOK)
	var list struct{ Invites []map[string]any }
	json.Unmarshal(listBody, &list)
	if len(list.Invites) != 1 || list.Invites[0]["status"] != "used" || list.Invites[0]["usedBy"] != bobName {
		t.Errorf("invite list = %s", listBody)
	}
	if strings.Contains(string(listBody), created.Code) {
		t.Error("invite list leaks the plaintext code")
	}
	// Used invites cannot be revoked; active ones can, and then are dead.
	root.jsonReq("DELETE", "/api/admin/invites/"+inviteID, nil, http.StatusNotFound)
	json.Unmarshal(root.jsonReq("POST", "/api/admin/invites", map[string]any{}, http.StatusCreated), &created)
	root.jsonReq("DELETE", "/api/admin/invites/"+created.Invite["id"].(string), nil, http.StatusOK)
	anon.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": uniqueUser("late"), "password": "late passphrase", "inviteCode": created.Code},
		http.StatusForbidden)
	// Malformed invite id is a 404, never a query.
	root.jsonReq("DELETE", "/api/admin/invites/not-a-uuid", nil, http.StatusNotFound)

	// Bob, a plain user, cannot touch the invite surface either.
	bob := e.newClient()
	bob.jsonReq("POST", "/api/auth/login",
		map[string]string{"username": bobName, "password": "bobs passphrase"}, http.StatusOK)
	if code := bob.statusOf("GET", "/api/admin/invites", nil, ""); code != http.StatusNotFound {
		t.Errorf("bob GET invites = %d, want 404", code)
	}
}
