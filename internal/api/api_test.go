package api

// End-to-end HTTP tests over a real server, real PostgreSQL, and a real
// storage directory: the endpoint-by-role authorization matrix, CSRF
// enforcement, upload validation (type spoofing, traversal names, oversize),
// bit-level tamper detection, deduplication semantics, and session hygiene.
// Skips unless TEST_DATABASE_URL is set.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"securevault/internal/audit"
	"securevault/internal/auth"
	"securevault/internal/database"
	"securevault/internal/files"
	"securevault/internal/storage"
)

const testMaxUpload = 64 << 10 // 64 KiB keeps the oversize test fast

var nameSeq atomic.Int64

type env struct {
	t       *testing.T
	server  *httptest.Server
	pool    *pgxpool.Pool
	dataDir string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWithPolicy(t, auth.RegistrationPolicy{Mode: auth.RegistrationOpen})
}

// newEnvWithPolicy builds the environment under a specific registration
// policy (see registration_test.go); newEnv uses open registration.
func newEnvWithPolicy(t *testing.T, policy auth.RegistrationPolicy) *env {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HTTP integration tests")
	}
	// Package-private database; see the matching comment in internal/auth.
	url += "_api"
	ctx := t.Context()

	pool, err := database.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"TRUNCATE users, sessions, login_failures, invites, blobs, nodes, grants, audit_events CASCADE"); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	kek := make([]byte, 32)
	copy(kek, []byte("integration-test-master-key-32bb"))
	store, err := storage.New(dataDir, kek)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	auditLog := audit.New(pool, logger)
	authSvc := auth.NewService(pool, auditLog)
	authSvc.SetRegistrationPolicy(policy)
	repo := files.NewRepo(pool, store, auditLog, testMaxUpload)

	srv := NewServer(authSvc, repo, auditLog, pool, logger, true, testMaxUpload, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &env{t: t, server: ts, pool: pool, dataDir: dataDir}
}

// client is one browser-like principal with its own cookie jar.
type client struct {
	t    *testing.T
	http *http.Client
	base string
}

func (e *env) newClient() *client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return &client{t: e.t, base: e.server.URL,
		http: &http.Client{Jar: jar}}
}

// anon is a client with no session at all.
func (e *env) anon() *client { return e.newClient() }

func (e *env) registerAndLogin(name string) *client {
	c := e.newClient()
	c.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": name, "password": "integration password"},
		http.StatusCreated)
	c.jsonReq("POST", "/api/auth/login",
		map[string]string{"username": name, "password": "integration password"},
		http.StatusOK)
	return c
}

func (e *env) promoteToAdmin(username string) {
	if _, err := e.pool.Exec(e.t.Context(),
		"UPDATE users SET role = 'admin' WHERE username = $1", username); err != nil {
		e.t.Fatal(err)
	}
}

func (c *client) csrf() string {
	u, _ := url.Parse(c.base)
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	return ""
}

// req performs a request, asserts the status, and returns the body.
func (c *client) req(method, path string, body io.Reader, contentType string, wantStatus int) []byte {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != "GET" && method != "HEAD" {
		req.Header.Set("X-CSRF-Token", c.csrf())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		c.t.Fatalf("%s %s = %d, want %d; body: %s", method, path, resp.StatusCode, wantStatus, data)
	}
	return data
}

func (c *client) jsonReq(method, path string, v any, wantStatus int) []byte {
	buf, _ := json.Marshal(v)
	return c.req(method, path, bytes.NewReader(buf), "application/json", wantStatus)
}

// statusOf performs a request and returns the raw status code (no assertion).
func (c *client) statusOf(method, path string, body io.Reader, contentType string) int {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != "GET" && method != "HEAD" {
		req.Header.Set("X-CSRF-Token", c.csrf())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func multipartBody(t *testing.T, filename, contentType string, content []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="file"; filename=%q`, filename)}
	h["Content-Type"] = []string{contentType}
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	part.Write(content)
	w.Close()
	return &buf, w.FormDataContentType()
}

func (c *client) upload(filename, contentType string, content []byte, wantStatus int) map[string]any {
	c.t.Helper()
	body, ct := multipartBody(c.t, filename, contentType, content)
	data := c.req("POST", "/api/files", body, ct, wantStatus)
	var out map[string]any
	json.Unmarshal(data, &out)
	return out
}

func uniqueUser(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, nameSeq.Add(1))
}

// --- scenarios ---

func TestValidLifecycle(t *testing.T) {
	e := newEnv(t)
	owner := e.registerAndLogin(uniqueUser("owner"))
	content := []byte("lifecycle test content")

	up := owner.upload("report.txt", "text/plain", content, http.StatusCreated)
	id := up["id"].(string)

	// List shows the file with the owner role.
	var list struct {
		Files []files.Node `json:"files"`
	}
	json.Unmarshal(owner.req("GET", "/api/files", nil, "", http.StatusOK), &list)
	if len(list.Files) != 1 || list.Files[0].MyRole != "owner" || list.Files[0].Name != "report.txt" {
		t.Fatalf("unexpected listing: %+v", list.Files)
	}

	// Download returns identical bytes with attachment-only headers.
	req, _ := http.NewRequest("GET", owner.base+"/api/files/"+id+"/download", nil)
	resp, err := owner.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, content) {
		t.Error("downloaded bytes differ from uploaded content")
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff on download")
	}

	// Rename, then delete.
	owner.jsonReq("PATCH", "/api/files/"+id, map[string]string{"name": "renamed.txt"}, http.StatusOK)
	owner.req("DELETE", "/api/files/"+id, nil, "", http.StatusOK)
	owner.req("GET", "/api/files/"+id+"/download", nil, "", http.StatusNotFound)
}

// TestEndpointRoleMatrix exercises every file endpoint as owner, editor,
// viewer, unrelated user, administrator, and unauthenticated client
// (proposal §7, authorization matrix).
func TestEndpointRoleMatrix(t *testing.T) {
	e := newEnv(t)
	ownerName := uniqueUser("owner")
	editorName, viewerName := uniqueUser("editor"), uniqueUser("viewer")

	owner := e.registerAndLogin(ownerName)
	editor := e.registerAndLogin(editorName)
	viewer := e.registerAndLogin(viewerName)
	unrelated := e.registerAndLogin(uniqueUser("unrelated"))
	adminName := uniqueUser("admin")
	admin := e.registerAndLogin(adminName)
	e.promoteToAdmin(adminName)
	anon := e.anon()

	up := owner.upload("matrix.txt", "text/plain", []byte("matrix content"), http.StatusCreated)
	id := up["id"].(string)
	owner.jsonReq("PUT", "/api/files/"+id+"/shares",
		map[string]string{"username": editorName, "role": "editor"}, http.StatusOK)
	owner.jsonReq("PUT", "/api/files/"+id+"/shares",
		map[string]string{"username": viewerName, "role": "viewer"}, http.StatusOK)

	renameBody := func() (io.Reader, string) {
		return strings.NewReader(`{"name":"x.txt"}`), "application/json"
	}
	// Share target must exist: only the owner row ever reaches the grantee
	// lookup, and re-granting viewer to the same user is an idempotent upsert.
	shareBody := func() (io.Reader, string) {
		return strings.NewReader(fmt.Sprintf(`{"username":%q,"role":"viewer"}`, viewerName)), "application/json"
	}

	matrix := []struct {
		principal string
		client    *client
		stat      int // GET metadata
		download  int
		rename    int // PATCH
		share     int // PUT shares
		del       int // DELETE
	}{
		{"editor", editor, 200, 200, 200, 404, 404},
		{"viewer", viewer, 200, 200, 404, 404, 404},
		{"unrelated", unrelated, 404, 404, 404, 404, 404},
		{"admin", admin, 404, 404, 404, 404, 404}, // account role ≠ file access
		{"anonymous", anon, 401, 401, 401, 401, 401},
		// Owner last: nobody above may delete, so the file survives them.
		{"owner", owner, 200, 200, 200, 200, 200},
	}

	for _, row := range matrix {
		if got := row.client.statusOf("GET", "/api/files/"+id, nil, ""); got != row.stat {
			t.Errorf("%s stat = %d, want %d", row.principal, got, row.stat)
		}
		if got := row.client.statusOf("GET", "/api/files/"+id+"/download", nil, ""); got != row.download {
			t.Errorf("%s download = %d, want %d", row.principal, got, row.download)
		}
		b, ct := renameBody()
		if got := row.client.statusOf("PATCH", "/api/files/"+id, b, ct); got != row.rename {
			t.Errorf("%s rename = %d, want %d", row.principal, got, row.rename)
		}
		b, ct = shareBody()
		if got := row.client.statusOf("PUT", "/api/files/"+id+"/shares", b, ct); got != row.share {
			t.Errorf("%s share = %d, want %d", row.principal, got, row.share)
		}
		if got := row.client.statusOf("DELETE", "/api/files/"+id, nil, ""); got != row.del {
			t.Errorf("%s delete = %d, want %d", row.principal, got, row.del)
		}
	}

	// Every denial above must be recorded in the audit log.
	var denials int
	if err := e.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE result = 'denied' AND action LIKE 'file.%'`).Scan(&denials); err != nil {
		t.Fatal(err)
	}
	if denials == 0 {
		t.Error("authorization denials produced no audit events")
	}

	// Admin endpoints: admin passes, regular user is denied and audited.
	admin.req("GET", "/api/admin/audit", nil, "", http.StatusOK)
	owner.req("GET", "/api/admin/users", nil, "", http.StatusNotFound)
}

func TestCSRFEnforcement(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("csrf"))

	// A state-changing request without the CSRF header is rejected even
	// with a valid session cookie.
	body, ct := multipartBody(t, "f.txt", "text/plain", []byte("x"))
	req, _ := http.NewRequest("POST", c.base+"/api/files", body)
	req.Header.Set("Content-Type", ct)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("upload without CSRF header = %d, want 403", resp.StatusCode)
	}

	// Wrong token is also rejected.
	body, ct = multipartBody(t, "f.txt", "text/plain", []byte("x"))
	req, _ = http.NewRequest("POST", c.base+"/api/files", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-CSRF-Token", "forged")
	resp, err = c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("upload with forged CSRF token = %d, want 403", resp.StatusCode)
	}
}

// pngHeader is a minimal valid PNG signature for magic-byte tests.
var pngHeader = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'}

func TestTypeSpoofingRejected(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("spoof"))

	// Honest declarations pass.
	c.upload("image.png", "image/png", pngHeader, http.StatusCreated)
	c.upload("notes.txt", "text/plain", []byte("plain text"), http.StatusCreated)

	// PNG bytes declared as text: signature mismatch.
	c.upload("fake.txt", "text/plain", pngHeader, http.StatusBadRequest)
	// Unsniffable bytes claiming to be an image: mismatch.
	c.upload("fake.png", "image/png", []byte{0x4d, 0x5a, 0x00, 0x01, 0x02, 0x03}, http.StatusBadRequest)
}

func TestTraversalFilenameNeutralized(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("traversal"))

	up := c.upload("../../etc/passwd", "text/plain", []byte("content"), http.StatusCreated)
	if name := up["name"].(string); name != "passwd" {
		t.Errorf("stored name = %q, want traversal stripped to %q", name, "passwd")
	}

	up = c.upload(`..\..\boot.ini`, "text/plain", []byte("content"), http.StatusCreated)
	if name := up["name"].(string); strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		t.Errorf("stored name %q still contains traversal characters", name)
	}

	// No user-influenced path may exist anywhere in the data directory.
	filepath.WalkDir(e.dataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, "passwd") || strings.Contains(path, "boot.ini") {
			t.Errorf("user-controlled name appears in storage path: %s", path)
		}
		return nil
	})
}

func TestOversizedUploadRejected(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("big"))

	// Null bytes make the sniffer report application/octet-stream, so type
	// validation passes and the size limit is what rejects the upload.
	c.upload("big.bin", "application/octet-stream",
		bytes.Repeat([]byte{0x00, 0xFF, 0x13, 0x37}, (testMaxUpload/4)+1), http.StatusRequestEntityTooLarge)

	// No object and no temp data may remain.
	var count int
	filepath.WalkDir(e.dataDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			count++
		}
		return nil
	})
	if count != 0 {
		t.Errorf("%d files remain in storage after rejected oversized upload", count)
	}
}

// TestIntegrityAttack flips one byte of the stored ciphertext and confirms
// the download is blocked, the client gets a controlled error, and the
// failure is audited (proposal §7, integrity attack).
func TestIntegrityAttack(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("victim"))

	up := c.upload("target.txt", "text/plain", []byte("bytes that will be attacked"), http.StatusCreated)
	id := up["id"].(string)

	// Find and corrupt the single stored object.
	var objPath string
	filepath.WalkDir(e.dataDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".obj") {
			objPath = path
		}
		return nil
	})
	if objPath == "" {
		t.Fatal("stored object not found")
	}
	raw, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(objPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	body := c.req("GET", "/api/files/"+id+"/download", nil, "", http.StatusInternalServerError)
	if !strings.Contains(string(body), "integrity") {
		t.Errorf("expected controlled integrity error, got: %s", body)
	}
	if strings.Contains(string(body), "attacked") {
		t.Error("plaintext leaked in error response")
	}

	var audited int
	if err := e.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action = 'file.download' AND result = 'error' AND reason = 'integrity_failure'`).
		Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited == 0 {
		t.Error("integrity failure was not audited")
	}
}

// TestDeduplication: identical content from two accounts shares one stored
// object; deletion by one account does not affect the other (proposal §7).
func TestDeduplication(t *testing.T) {
	e := newEnv(t)
	a := e.registerAndLogin(uniqueUser("dedupa"))
	b := e.registerAndLogin(uniqueUser("dedupb"))
	content := []byte("identical bytes uploaded twice")

	upA := a.upload("a.txt", "text/plain", content, http.StatusCreated)
	b.upload("b.txt", "text/plain", content, http.StatusCreated)

	var blobs, refs int
	if err := e.pool.QueryRow(t.Context(),
		"SELECT count(*), COALESCE(sum(ref_count), 0) FROM blobs").Scan(&blobs, &refs); err != nil {
		t.Fatal(err)
	}
	if blobs != 1 || refs != 2 {
		t.Fatalf("blobs = %d (want 1), total refs = %d (want 2)", blobs, refs)
	}

	// A deletes their node; B's copy must remain fully readable.
	a.req("DELETE", "/api/files/"+upA["id"].(string), nil, "", http.StatusOK)

	var list struct {
		Files []files.Node `json:"files"`
	}
	json.Unmarshal(b.req("GET", "/api/files", nil, "", http.StatusOK), &list)
	if len(list.Files) != 1 {
		t.Fatalf("B's listing has %d files after A's delete, want 1", len(list.Files))
	}
	got := b.req("GET", "/api/files/"+list.Files[0].ID+"/download", nil, "", http.StatusOK)
	if !bytes.Equal(got, content) {
		t.Error("B's content damaged by A's deletion")
	}
}

func TestSessionHygiene(t *testing.T) {
	e := newEnv(t)
	name := uniqueUser("hygiene")
	c := e.newClient()

	c.jsonReq("POST", "/api/auth/register",
		map[string]string{"username": name, "password": "hygiene password"}, http.StatusCreated)

	// Inspect Set-Cookie attributes on login directly.
	buf, _ := json.Marshal(map[string]string{"username": name, "password": "hygiene password"})
	resp, err := c.http.Post(c.base+"/api/auth/login", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	var sessionSeen bool
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			sessionSeen = true
			if !ck.HttpOnly {
				t.Error("session cookie is not HttpOnly")
			}
			if ck.SameSite != http.SameSiteStrictMode {
				t.Error("session cookie is not SameSite=Strict")
			}
		}
	}
	if !sessionSeen {
		t.Fatal("no session cookie set on login")
	}

	// Session tokens at rest are hashes, never the cookie value.
	u, _ := url.Parse(c.base)
	var cookieVal string
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			cookieVal = ck.Value
		}
	}
	var stored int
	if err := e.pool.QueryRow(t.Context(),
		"SELECT count(*) FROM sessions WHERE encode(token_hash, 'base64') = $1 OR encode(token_hash, 'hex') = $1",
		cookieVal).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Error("session token stored in recoverable form")
	}

	// Logout, then replay the old cookie: must be rejected.
	c.req("POST", "/api/auth/logout", nil, "", http.StatusOK)
	req, _ := http.NewRequest("GET", c.base+"/api/auth/me", nil)
	// Attacker-side test fixture: replaying a stolen token value, so no
	// client cookie flags apply (the server sets the real flags).
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure, go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookieVal})
	resp, err = c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("replayed token after logout = %d, want 401", resp.StatusCode)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.server.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	for header, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q; got %q", directive, csp)
		}
	}
}

// HSTS is the one header that must depend on mode: emitted for every
// non-dev build (TLS is a precondition there) and never on plain-HTTP dev.
// Exercised on the middleware directly so it runs without a database.
func TestHSTSFollowsDevMode(t *testing.T) {
	for _, tc := range []struct{ dev, want bool }{{true, false}, {false, true}} {
		h := withSecurityHeaders(tc.dev, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		got := rec.Header().Get("Strict-Transport-Security") != ""
		if got != tc.want {
			t.Errorf("dev=%v: HSTS present=%v, want %v", tc.dev, got, tc.want)
		}
		if tc.want && rec.Header().Get("Strict-Transport-Security") != "max-age=31536000; includeSubDomains" {
			t.Errorf("unexpected HSTS value %q", rec.Header().Get("Strict-Transport-Security"))
		}
	}
}

func TestMalformedInputRejected(t *testing.T) {
	e := newEnv(t)
	c := e.registerAndLogin(uniqueUser("fuzz"))

	// Unknown JSON fields are rejected (strict schemas).
	c.jsonReq("POST", "/api/auth/password",
		map[string]string{"currentPassword": "x", "newPassword": "y", "extra": "field"},
		http.StatusBadRequest)

	// Malformed identifiers are indistinguishable from missing files.
	for _, id := range []string{"not-a-uuid", "../../etc", "00000000-0000-0000-0000-00000000000g"} {
		if got := c.statusOf("GET", "/api/files/"+url.PathEscape(id), nil, ""); got != http.StatusNotFound {
			t.Errorf("malformed id %q = %d, want 404", id, got)
		}
	}

	// Oversized JSON body is rejected.
	huge := fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", maxJSONBody+1))
	up := c.upload("j.txt", "text/plain", []byte("z"), http.StatusCreated)
	if got := c.statusOf("PATCH", "/api/files/"+up["id"].(string),
		strings.NewReader(huge), "application/json"); got != http.StatusBadRequest {
		t.Errorf("oversized JSON body = %d, want 400", got)
	}
}
