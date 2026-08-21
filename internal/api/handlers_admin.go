package api

import (
	"net/http"
	"time"

	"securevault/internal/auth"
)

// Invite administration: issuing, listing, and revoking one-time
// registration codes. Account listing and audit review live in
// handlers_files.go alongside the other read-only admin queries.

type inviteResponse struct {
	ID        string     `json:"id"`
	Note      string     `json:"note"`
	CreatedBy string     `json:"createdBy"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedBy    string     `json:"usedBy"`
	UsedAt    *time.Time `json:"usedAt"`
	RevokedAt *time.Time `json:"revokedAt"`
	Status    string     `json:"status"` // active | used | revoked | expired
}

func toInviteResponse(i auth.Invite) inviteResponse {
	return inviteResponse{
		ID: i.ID, Note: i.Note, CreatedBy: i.CreatedBy,
		CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt,
		UsedBy: i.UsedBy, UsedAt: i.UsedAt, RevokedAt: i.RevokedAt,
		Status: i.Status(),
	}
}

func (s *Server) handleAdminInvites(w http.ResponseWriter, r *http.Request) {
	list, err := s.auth.ListInvites(r.Context(), userFrom(r.Context()))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	out := make([]inviteResponse, 0, len(list))
	for _, i := range list {
		out = append(out, toInviteResponse(i))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (s *Server) handleAdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note     string `json:"note"`
		TTLHours int    `json:"ttlHours"` // 0 = service default (7 days)
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.TTLHours < 0 {
		writeError(w, http.StatusBadRequest, auth.ErrInvitePolicy.Error())
		return
	}
	code, inv, err := s.auth.CreateInvite(r.Context(), userFrom(r.Context()),
		req.Note, time.Duration(req.TTLHours)*time.Hour)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	// The plaintext code appears in this one response and nowhere else.
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":   code,
		"invite": toInviteResponse(*inv),
	})
}

func (s *Server) handleAdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		writeError(w, http.StatusNotFound, auth.ErrInviteNotFound.Error())
		return
	}
	if err := s.auth.RevokeInvite(r.Context(), userFrom(r.Context()), id); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
