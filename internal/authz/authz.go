// Package authz is SecureVault's single authorization choke point.
// Every file-touching request — list, download, rename, share, delete — is
// decided by Can, a pure deny-by-default function. There is deliberately no
// other place in the codebase that reasons about roles.
//
// The administrator account role governs account administration and audit
// review only; it grants NO access to file content through the sharing
// model (proposal §4.3).
package authz

import "securevault/internal/auth"

// Action is something a principal can attempt on a file node.
type Action string

const (
	// ActionView covers reading file metadata (name, size, times, sharing).
	ActionView Action = "view"
	// ActionDownload covers retrieving decrypted file content.
	ActionDownload Action = "download"
	// ActionRename covers changing the display name.
	ActionRename Action = "rename"
	// ActionDelete covers removing the node (and dereferencing its blob).
	ActionDelete Action = "delete"
	// ActionShare covers granting and revoking editor/viewer roles.
	ActionShare Action = "share"
)

// Share-grant roles as stored in the grants table.
const (
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// NodeACL is the complete access-control state of one file node.
type NodeACL struct {
	OwnerID string
	// Grants maps user ID -> RoleEditor or RoleViewer.
	Grants map[string]string
}

// rolePermissions is the entire sharing-role permission matrix (proposal
// §4.3). Owners are handled explicitly in Can; anything absent here is
// denied.
var rolePermissions = map[string]map[Action]bool{
	RoleEditor: {
		ActionView:     true,
		ActionDownload: true,
		ActionRename:   true,
	},
	RoleViewer: {
		ActionView:     true,
		ActionDownload: true,
	},
}

// Can reports whether u may perform action on a node with the given ACL.
// It denies by default: nil user, unknown role, unknown action, and the
// admin account role all fall through to false unless a grant says
// otherwise.
func Can(u *auth.User, acl NodeACL, action Action) bool {
	if u == nil || u.ID == "" {
		return false
	}
	if u.ID == acl.OwnerID {
		// Owners hold every defined action.
		switch action {
		case ActionView, ActionDownload, ActionRename, ActionDelete, ActionShare:
			return true
		}
		return false
	}
	if role, ok := acl.Grants[u.ID]; ok {
		return rolePermissions[role][action]
	}
	return false
}

// CanAdministrate reports whether u may invoke account-administration and
// audit-review endpoints. It is intentionally separate from Can: holding it
// conveys no path to file plaintext.
func CanAdministrate(u *auth.User) bool {
	return u != nil && u.IsAdmin()
}
