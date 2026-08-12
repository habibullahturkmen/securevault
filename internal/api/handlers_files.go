package api

import (
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"securevault/internal/files"
)

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.files.List(r.Context(), userFrom(r.Context()))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": nodes})
}

// handleUpload streams a multipart upload. The size limit is enforced twice:
// MaxBytesReader caps the whole request while receiving, and the storage
// engine independently enforces the content limit.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload+(64<<10)) // + multipart framing

	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}

	for {
		part, err := mr.NextPart()
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "file exceeds the upload size limit")
				return
			}
			writeError(w, http.StatusBadRequest, "no file field in upload")
			return
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}

		node, err := s.files.Upload(r.Context(), userFrom(r.Context()),
			part.FileName(), part.Header.Get("Content-Type"), part)
		part.Close()
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				err = files.ErrTooLarge
			}
			s.writeServiceError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, node)
		return
	}
}

func (s *Server) handleStat(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	node, grants, err := s.files.Stat(r.Context(), userFrom(r.Context()), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	resp := map[string]any{"file": node}
	if grants != nil {
		resp["shares"] = grants
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDownload streams verified plaintext as an attachment. The response
// is download-only by policy: Content-Disposition attachment, nosniff, and
// a filename escaped via RFC 2183 parameter encoding.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	node, plain, err := s.files.Download(r.Context(), userFrom(r.Context()), id)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", node.MimeType)
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": node.Name}))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(plain)), 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(plain)
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	node, err := s.files.Rename(r.Context(), userFrom(r.Context()), id, req.Name)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	if err := s.files.Delete(r.Context(), userFrom(r.Context()), id); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.files.Share(r.Context(), userFrom(r.Context()), id, req.Username, req.Role); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "shared"})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, files.ErrNotFound.Error())
		return
	}
	username := r.PathValue("username")
	if len(username) > 64 {
		writeError(w, http.StatusBadRequest, "malformed username")
		return
	}
	if err := s.files.Revoke(r.Context(), userFrom(r.Context()), id, username); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- administration (account and audit review only) ---

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pool.Query(r.Context(), `
		SELECT id, username, role, created_at FROM users ORDER BY created_at`)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	defer rows.Close()

	type row struct {
		ID        string    `json:"id"`
		Username  string    `json:"username"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"createdAt"`
	}
	users := []row{}
	for rows.Next() {
		var u row
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		users = append(users, u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "limit must be 1-1000")
			return
		}
		limit = n
	}

	rows, err := s.pool.Query(r.Context(), `
		SELECT at, actor_name, action, target, result, reason, request_id
		FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	defer rows.Close()

	type event struct {
		At        time.Time `json:"at"`
		Actor     string    `json:"actor"`
		Action    string    `json:"action"`
		Target    string    `json:"target"`
		Result    string    `json:"result"`
		Reason    string    `json:"reason"`
		RequestID string    `json:"requestId"`
	}
	events := []event{}
	for rows.Next() {
		var e event
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Result, &e.Reason, &e.RequestID); err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		events = append(events, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
