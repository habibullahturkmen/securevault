package api

import (
	"net/http"
)

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	credentialsRequest
	// InviteCode is required only when the registration policy is invite.
	InviteCode string `json:"inviteCode"`
}

type userResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.auth.Register(r.Context(), req.Username, req.Password, req.InviteCode)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, userResponse{ID: u.ID, Username: u.Username, Role: u.Role})
}

// handleRegistrationStatus tells the sign-up form which fields to show.
// Public by design: it reveals the policy, never any account.
func (s *Server) handleRegistrationStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.auth.RegistrationStatus(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":                   st.Mode,
		"acceptingRegistrations": st.Accepting,
		"inviteRequired":         st.InviteRequired,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, u, err := s.auth.Login(r.Context(), req.Username, req.Password, clientAddr(r))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	if err := s.setSessionCookies(w, token); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userResponse{ID: u.ID, Username: u.Username, Role: u.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionCookie)
	if err := s.auth.Logout(r.Context(), cookie.Value, userFrom(r.Context())); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.clearSessionCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	writeJSON(w, http.StatusOK, userResponse{ID: u.ID, Username: u.Username, Role: u.Role})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, err := s.auth.ChangePassword(r.Context(), userFrom(r.Context()),
		req.CurrentPassword, req.NewPassword)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	// All sessions were revoked; hand the client its rotated session.
	if err := s.setSessionCookies(w, token); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}
