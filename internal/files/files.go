// Package files implements the file API's data layer: uploads through the
// content-addressed store, authorized retrieval, sharing grants, renames,
// and reference-counted deletion. Every operation consults the single
// authorization choke point (authz.Can) and records an audit event for both
// successes and denials.
//
// Transactional discipline for uploads follows the storage engine contract:
// the ciphertext object is published to disk BEFORE the metadata transaction
// commits, so a crash yields at worst an invisible orphan object, never a
// visible node without content.
package files

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"securevault/internal/audit"
	"securevault/internal/auth"
	"securevault/internal/authz"
	"securevault/internal/storage"
)

var (
	// ErrNotFound is returned when a node does not exist OR the caller has
	// no grant that would let them learn it exists. The two cases are
	// deliberately indistinguishable to prevent resource enumeration; the
	// audit log records which one actually happened.
	ErrNotFound = errors.New("file not found")
	// ErrIntegrity is returned when stored content fails verification.
	// The client receives a controlled error; the event is audited.
	ErrIntegrity = errors.New("stored object failed integrity verification")
	// ErrTooLarge mirrors the storage engine's size rejection.
	ErrTooLarge = storage.ErrTooLarge
)

// Node is a user-visible file: metadata plus the caller's effective role.
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MimeType  string    `json:"mimeType"`
	Size      int64     `json:"size"`
	OwnerName string    `json:"owner"`
	MyRole    string    `json:"myRole"` // owner | editor | viewer
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Grant is one sharing entry on a node, visible to its owner.
type Grant struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Repo coordinates PostgreSQL metadata, the storage engine, and audit.
type Repo struct {
	pool     *pgxpool.Pool
	store    *storage.Store
	audit    *audit.Logger
	maxBytes int64
}

func NewRepo(pool *pgxpool.Pool, store *storage.Store, auditLog *audit.Logger, maxBytes int64) *Repo {
	return &Repo{pool: pool, store: store, audit: auditLog, maxBytes: maxBytes}
}

// Upload validates, stages, deduplicates, and records a new file owned by u.
func (r *Repo) Upload(ctx context.Context, u *auth.User, filename, declaredMIME string, body io.Reader) (*Node, error) {
	name := SanitizeFilename(filename)

	// Sniff magic bytes from the head of the stream, then reassemble it.
	head := make([]byte, 512)
	n, err := io.ReadFull(body, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("files: read upload: %w", err)
	}
	mimeType, err := ValidateContent(declaredMIME, head[:n])
	if err != nil {
		r.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: u.Username, Action: "file.upload",
			Target: name, Result: audit.ResultDenied, Reason: "type_mismatch",
		})
		return nil, err
	}

	staged, err := r.store.Stage(io.MultiReader(bytes.NewReader(head[:n]), body), r.maxBytes)
	if err != nil {
		if errors.Is(err, storage.ErrTooLarge) {
			r.audit.Record(ctx, audit.Event{
				ActorID: u.ID, ActorName: u.Username, Action: "file.upload",
				Target: name, Result: audit.ResultDenied, Reason: "too_large",
			})
		}
		return nil, err
	}
	defer staged.Abort() // no-op once committed

	// Two attempts: a concurrent first-upload of identical new content can
	// win the blobs INSERT; the retry then takes the dedup path.
	var node *Node
	for attempt := 0; attempt < 2; attempt++ {
		node, err = r.insertUpload(ctx, u, name, mimeType, staged)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && attempt == 0 {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "file.upload",
		Target: node.ID, Result: audit.ResultOK,
	})
	return node, nil
}

func (r *Repo) insertUpload(ctx context.Context, u *auth.User, name, mimeType string, staged *storage.Staged) (*Node, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("files: begin upload tx: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	hash := staged.Hash[:]
	var refs int
	err = tx.QueryRow(ctx,
		`SELECT ref_count FROM blobs WHERE hash = $1 FOR UPDATE`, hash).Scan(&refs)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// First reference: record the blob, then publish the ciphertext
		// BEFORE the transaction commits (see package comment).
		if _, err := tx.Exec(ctx, `
			INSERT INTO blobs (hash, size_bytes, wrapped_dek, ref_count)
			VALUES ($1, $2, $3, 1)`, hash, staged.Size, staged.WrappedDEK); err != nil {
			return nil, err
		}
		if err := staged.Commit(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("files: check blob: %w", err)
	default:
		// Deduplication: content already stored; add a reference and keep
		// the existing object and DEK.
		if _, err := tx.Exec(ctx,
			`UPDATE blobs SET ref_count = ref_count + 1 WHERE hash = $1`, hash); err != nil {
			return nil, err
		}
		staged.Abort()
	}

	node := &Node{Name: name, MimeType: mimeType, Size: staged.Size,
		OwnerName: u.Username, MyRole: "owner"}
	if err := tx.QueryRow(ctx, `
		INSERT INTO nodes (owner_id, blob_hash, display_name, mime_type)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`,
		u.ID, hash, name, mimeType).Scan(&node.ID, &node.CreatedAt, &node.UpdatedAt); err != nil {
		return nil, fmt.Errorf("files: insert node: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("files: commit upload: %w", err)
	}
	return node, nil
}

// List returns every node the user owns or holds a grant on.
func (r *Repo) List(ctx context.Context, u *auth.User) ([]Node, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT n.id, n.display_name, n.mime_type, b.size_bytes,
		       ou.username, n.created_at, n.updated_at,
		       CASE WHEN n.owner_id = $1 THEN 'owner' ELSE g.role END
		FROM nodes n
		JOIN blobs b ON b.hash = n.blob_hash
		JOIN users ou ON ou.id = n.owner_id
		LEFT JOIN grants g ON g.node_id = n.id AND g.grantee_id = $1
		WHERE n.owner_id = $1 OR g.grantee_id IS NOT NULL
		ORDER BY n.created_at DESC`, u.ID)
	if err != nil {
		return nil, fmt.Errorf("files: list: %w", err)
	}
	defer rows.Close()

	nodes := []Node{}
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.MimeType, &n.Size,
			&n.OwnerName, &n.CreatedAt, &n.UpdatedAt, &n.MyRole); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// nodeState is everything needed to authorize and act on one node.
type nodeState struct {
	Node
	ownerID    string
	blobHash   []byte
	wrappedDEK []byte
	acl        authz.NodeACL
}

func (r *Repo) loadNode(ctx context.Context, nodeID string) (*nodeState, error) {
	st := &nodeState{}
	err := r.pool.QueryRow(ctx, `
		SELECT n.id, n.display_name, n.mime_type, b.size_bytes, ou.username,
		       n.created_at, n.updated_at, n.owner_id, n.blob_hash, b.wrapped_dek
		FROM nodes n
		JOIN blobs b ON b.hash = n.blob_hash
		JOIN users ou ON ou.id = n.owner_id
		WHERE n.id = $1`, nodeID).
		Scan(&st.ID, &st.Name, &st.MimeType, &st.Size, &st.OwnerName,
			&st.CreatedAt, &st.UpdatedAt, &st.ownerID, &st.blobHash, &st.wrappedDEK)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("files: load node: %w", err)
	}

	st.acl = authz.NodeACL{OwnerID: st.ownerID, Grants: map[string]string{}}
	rows, err := r.pool.Query(ctx,
		`SELECT grantee_id, role FROM grants WHERE node_id = $1`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("files: load grants: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, role string
		if err := rows.Scan(&id, &role); err != nil {
			return nil, err
		}
		st.acl.Grants[id] = role
	}
	return st, rows.Err()
}

// authorize loads the node and evaluates the central choke point, auditing
// and normalizing every denial to ErrNotFound (no resource enumeration).
func (r *Repo) authorize(ctx context.Context, u *auth.User, nodeID string, action authz.Action) (*nodeState, error) {
	st, err := r.loadNode(ctx, nodeID)
	if errors.Is(err, ErrNotFound) {
		r.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: u.Username, Action: "file." + string(action),
			Target: nodeID, Result: audit.ResultDenied, Reason: "not_found",
		})
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !authz.Can(u, st.acl, action) {
		r.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: u.Username, Action: "file." + string(action),
			Target: nodeID, Result: audit.ResultDenied, Reason: "no_grant",
		})
		return nil, ErrNotFound
	}
	if u.ID == st.ownerID {
		st.MyRole = "owner"
	} else {
		st.MyRole = st.acl.Grants[u.ID]
	}
	return st, nil
}

// Stat returns node metadata, plus the grant list when the caller may share
// (owners only) — grantees see the file, not who else has it.
func (r *Repo) Stat(ctx context.Context, u *auth.User, nodeID string) (*Node, []Grant, error) {
	st, err := r.authorize(ctx, u, nodeID, authz.ActionView)
	if err != nil {
		return nil, nil, err
	}

	var grants []Grant
	if authz.Can(u, st.acl, authz.ActionShare) {
		rows, err := r.pool.Query(ctx, `
			SELECT us.username, g.role FROM grants g
			JOIN users us ON us.id = g.grantee_id
			WHERE g.node_id = $1 ORDER BY us.username`, nodeID)
		if err != nil {
			return nil, nil, fmt.Errorf("files: list grants: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g Grant
			if err := rows.Scan(&g.Username, &g.Role); err != nil {
				return nil, nil, err
			}
			grants = append(grants, g)
		}
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}
	return &st.Node, grants, nil
}

// Download authorizes, retrieves, decrypts, and verifies the content.
// Integrity failure is audited and reported as a controlled error; plaintext
// is never released unverified (storage engine contract).
func (r *Repo) Download(ctx context.Context, u *auth.User, nodeID string) (*Node, []byte, error) {
	st, err := r.authorize(ctx, u, nodeID, authz.ActionDownload)
	if err != nil {
		return nil, nil, err
	}

	plain, err := r.store.Open(st.blobHash, st.wrappedDEK)
	if err != nil {
		reason := "storage_error"
		if errors.Is(err, storage.ErrCorrupt) || errors.Is(err, storage.ErrNotFound) {
			reason = "integrity_failure"
		}
		r.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorName: u.Username, Action: "file.download",
			Target: nodeID, Result: audit.ResultError, Reason: reason,
		})
		return nil, nil, ErrIntegrity
	}

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "file.download",
		Target: nodeID, Result: audit.ResultOK,
	})
	return &st.Node, plain, nil
}

// Rename updates the display name (owner or editor).
func (r *Repo) Rename(ctx context.Context, u *auth.User, nodeID, newName string) (*Node, error) {
	st, err := r.authorize(ctx, u, nodeID, authz.ActionRename)
	if err != nil {
		return nil, err
	}

	name := SanitizeFilename(newName)
	if err := r.pool.QueryRow(ctx, `
		UPDATE nodes SET display_name = $1, updated_at = now()
		WHERE id = $2 RETURNING updated_at`, name, nodeID).Scan(&st.UpdatedAt); err != nil {
		return nil, fmt.Errorf("files: rename: %w", err)
	}
	st.Name = name

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "file.rename",
		Target: nodeID, Result: audit.ResultOK,
	})
	return &st.Node, nil
}

// Delete removes the node and dereferences its blob; the last reference
// removes the blob row and the ciphertext object. The audit event is
// minimal and non-sensitive (proposal §5.2.8).
func (r *Repo) Delete(ctx context.Context, u *auth.User, nodeID string) error {
	st, err := r.authorize(ctx, u, nodeID, authz.ActionDelete)
	if err != nil {
		return err
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("files: begin delete tx: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	if _, err := tx.Exec(ctx, `DELETE FROM nodes WHERE id = $1`, nodeID); err != nil {
		return fmt.Errorf("files: delete node: %w", err)
	}
	var refs int
	if err := tx.QueryRow(ctx, `
		UPDATE blobs SET ref_count = ref_count - 1
		WHERE hash = $1 RETURNING ref_count`, st.blobHash).Scan(&refs); err != nil {
		return fmt.Errorf("files: dereference blob: %w", err)
	}
	if refs == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM blobs WHERE hash = $1`, st.blobHash); err != nil {
			return fmt.Errorf("files: delete blob row: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("files: commit delete: %w", err)
	}

	// Object removal happens after the metadata commit: a crash here leaves
	// an orphan file, which is invisible and reclaimed on re-upload.
	if refs == 0 {
		if err := r.store.Remove(st.blobHash); err != nil {
			return err
		}
	}

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "file.delete",
		Target: nodeID, Result: audit.ResultOK,
	})
	return nil
}

// Share grants role (editor|viewer) on the node to another registered user.
func (r *Repo) Share(ctx context.Context, u *auth.User, nodeID, granteeName, role string) error {
	if role != authz.RoleEditor && role != authz.RoleViewer {
		return fmt.Errorf("%w: role must be editor or viewer", ErrValidation)
	}
	st, err := r.authorize(ctx, u, nodeID, authz.ActionShare)
	if err != nil {
		return err
	}

	var granteeID string
	err = r.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE username = $1`, granteeName).Scan(&granteeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: no such user", ErrValidation)
	}
	if err != nil {
		return fmt.Errorf("files: look up grantee: %w", err)
	}
	if granteeID == st.ownerID {
		return fmt.Errorf("%w: cannot grant to the owner", ErrValidation)
	}

	if _, err := r.pool.Exec(ctx, `
		INSERT INTO grants (node_id, grantee_id, role, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (node_id, grantee_id) DO UPDATE SET role = EXCLUDED.role`,
		nodeID, granteeID, role, u.ID); err != nil {
		return fmt.Errorf("files: grant: %w", err)
	}

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "share.grant",
		Target: nodeID, Result: audit.ResultOK, Reason: role + ":" + granteeName,
	})
	return nil
}

// Revoke removes a grantee's role on the node.
func (r *Repo) Revoke(ctx context.Context, u *auth.User, nodeID, granteeName string) error {
	if _, err := r.authorize(ctx, u, nodeID, authz.ActionShare); err != nil {
		return err
	}

	tag, err := r.pool.Exec(ctx, `
		DELETE FROM grants g USING users us
		WHERE g.node_id = $1 AND g.grantee_id = us.id AND us.username = $2`,
		nodeID, granteeName)
	if err != nil {
		return fmt.Errorf("files: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: no such grant", ErrValidation)
	}

	r.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorName: u.Username, Action: "share.revoke",
		Target: nodeID, Result: audit.ResultOK, Reason: granteeName,
	})
	return nil
}
