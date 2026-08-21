// Package api is SecureVault's HTTP surface: route table, middleware chain,
// strict request decoding, and uniform JSON errors. Handlers translate HTTP
// into calls on the auth service and files repository; every security
// decision lives in those layers and in authz — never in a handler.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"securevault/internal/audit"
	"securevault/internal/auth"
	"securevault/internal/files"
)

const (
	sessionCookie = "sv_session"
	csrfCookie    = "sv_csrf"

	// maxJSONBody bounds every JSON request body.
	maxJSONBody = 16 << 10 // 16 KiB
)

// Server wires the HTTP layer to the application services.
type Server struct {
	auth      *auth.Service
	files     *files.Repo
	audit     *audit.Logger
	pool      *pgxpool.Pool // admin read-only queries (users, audit review)
	log       *slog.Logger
	devMode   bool
	maxUpload int64
	ui        fs.FS // embedded web interface; nil in dev (Vite serves it)
}

func NewServer(authSvc *auth.Service, repo *files.Repo, auditLog *audit.Logger,
	pool *pgxpool.Pool, log *slog.Logger, devMode bool, maxUpload int64, ui fs.FS) *Server {
	return &Server{
		auth: authSvc, files: repo, audit: auditLog, pool: pool,
		log: log, devMode: devMode, maxUpload: maxUpload, ui: ui,
	}
}

// Handler builds the complete route table wrapped in the middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Authentication.
	mux.HandleFunc("POST /api/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.requireCSRF(s.handleChangePassword)))
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	// Files and sharing.
	mux.HandleFunc("GET /api/files", s.requireAuth(s.handleList))
	mux.HandleFunc("POST /api/files", s.requireAuth(s.requireCSRF(s.handleUpload)))
	mux.HandleFunc("GET /api/files/{id}", s.requireAuth(s.handleStat))
	mux.HandleFunc("GET /api/files/{id}/download", s.requireAuth(s.handleDownload))
	mux.HandleFunc("PATCH /api/files/{id}", s.requireAuth(s.requireCSRF(s.handleRename)))
	mux.HandleFunc("DELETE /api/files/{id}", s.requireAuth(s.requireCSRF(s.handleDelete)))
	mux.HandleFunc("PUT /api/files/{id}/shares", s.requireAuth(s.requireCSRF(s.handleShare)))
	mux.HandleFunc("DELETE /api/files/{id}/shares/{username}", s.requireAuth(s.requireCSRF(s.handleRevoke)))

	// Administration: account review and audit review only — no file access.
	mux.HandleFunc("GET /api/admin/users", s.requireAuth(s.requireAdmin(s.handleAdminUsers)))
	mux.HandleFunc("GET /api/admin/audit", s.requireAuth(s.requireAdmin(s.handleAdminAudit)))

	// Unknown API routes get a JSON 404 rather than the SPA fallback.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})

	if s.ui != nil {
		mux.Handle("/", s.spaHandler())
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound,
				"no embedded UI in this build; use the Vite dev server (make web-dev)")
		})
	}

	var h http.Handler = mux
	h = withSecurityHeaders(s.devMode, h)
	h = s.withLogging(h)
	h = withRecovery(s.log, h)
	h = withRequestID(h)
	return h
}

// spaHandler serves the embedded single-page app: exact static assets when
// they exist, index.html for everything else (client-side routing).
func (s *Server) spaHandler() http.Handler {
	static := http.FileServerFS(s.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := s.ui.Open(path); err == nil {
				f.Close()
				static.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(s.ui, "index.html")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// index is the compiled, embedded index.html — a build artifact,
		// never user data, so no output encoding applies here.
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		w.Write(index)
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		s.log.Info("request",
			"request_id", requestIDFrom(r.Context()),
			"method", r.Method, "path", r.URL.Path)
	})
}

// --- cookies ---

func (s *Server) setSessionCookies(w http.ResponseWriter, token string) error {
	// Secure is set for every non-dev build; the rule cannot see through
	// the `!s.devMode` conditional (dev = plain-HTTP localhost only).
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: !s.devMode, SameSite: http.SameSiteStrictMode,
		MaxAge: 24 * 60 * 60,
	})
	// Fresh CSRF token alongside every fresh session.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	// The CSRF cookie is deliberately NOT HttpOnly: the double-submit
	// pattern requires the same-origin SPA to read it and echo it in the
	// X-CSRF-Token header. It carries no session authority. Secure is set
	// outside dev mode as above.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly, go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: base64.RawURLEncoding.EncodeToString(buf), Path: "/",
		HttpOnly: false, Secure: !s.devMode, SameSite: http.SameSiteStrictMode,
		MaxAge: 24 * 60 * 60,
	})
	return nil
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		// Expired empty deletion cookies; flags mirror the originals
		// (session HttpOnly, CSRF readable), Secure outside dev mode.
		// nosemgrep: go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly, go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie, Secure: !s.devMode,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// --- request/response helpers ---

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// pathUUID validates a route parameter as a UUID before it ever reaches a
// query. Malformed identifiers are indistinguishable from missing files.
func pathUUID(r *http.Request, name string) (string, bool) {
	v := strings.ToLower(r.PathValue(name))
	return v, uuidRe.MatchString(v)
}

// decodeJSON enforces the strict request-schema policy: size-capped bodies,
// unknown fields rejected, exactly one JSON value.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("malformed request body")
	}
	if dec.More() {
		return errors.New("malformed request body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeServiceError maps service-layer errors to uniform client responses.
// Anything unrecognized is a 500 with no internal detail.
func (s *Server) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, auth.ErrThrottled):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, auth.ErrSessionInvalid):
		writeError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, auth.ErrUsernameTaken):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, auth.ErrUsernamePolicy), errors.Is(err, auth.ErrPasswordPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, files.ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, files.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, files.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "file exceeds the upload size limit")
	case errors.Is(err, files.ErrIntegrity):
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		s.log.Error("internal error",
			"request_id", requestIDFrom(r.Context()), "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func (s *Server) auditDenied(r *http.Request, action, target string) {
	u := userFrom(r.Context())
	e := audit.Event{
		Action: action, Target: target,
		Result: audit.ResultDenied, Reason: "no_grant",
		RequestID: requestIDFrom(r.Context()),
	}
	if u != nil {
		e.ActorID, e.ActorName = u.ID, u.Username
	}
	s.audit.Record(r.Context(), e)
}
