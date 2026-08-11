package handlers

import (
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"net/http"
	"strings"
)

type Auth struct {
	Service    auth.Service
	Production bool
}
type loginRequest struct {
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Password     string `json:"password"`
}

func (h Auth) Login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "login request is invalid")
		return
	}
	result, err := h.Service.Login(r.Context(), strings.TrimSpace(input.Organization), strings.TrimSpace(input.Email), input.Password)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		middleware.WriteError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "email, password or organization is invalid")
		return
	}
	if errors.Is(err, auth.ErrMFAEnrollmentRequired) {
		middleware.WriteError(w, r, http.StatusForbidden, "MFA_ENROLLMENT_REQUIRED", "multi-factor authentication enrollment is required by policy")
		return
	}
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "LOGIN_FAILED", "login could not be completed")
		return
	}
	if result.MFARequired {
		http.SetCookie(w, &http.Cookie{Name: "netscope_mfa_challenge", Value: result.MFAChallenge, Path: "/api/v1/auth/mfa", HttpOnly: true, Secure: h.Production, SameSite: http.SameSiteStrictMode, MaxAge: 300})
		middleware.JSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{"mfaRequired": true}})
		return
	}
	policy := auth.CookiePolicy(h.Production)
	http.SetCookie(w, &http.Cookie{Name: policy.Name, Value: result.SessionToken, Path: "/", HttpOnly: policy.HTTPOnly, Secure: policy.Secure, SameSite: http.SameSiteLaxMode, MaxAge: policy.MaxAgeSeconds})
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]any{"userId": result.UserID, "organizationId": result.OrganizationID, "mfaRequired": false}})
}

type mfaRequest struct {
	Code string `json:"code"`
}

func (h Auth) MFA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("netscope_mfa_challenge")
	if err != nil {
		middleware.WriteError(w, r, http.StatusUnauthorized, "MFA_CHALLENGE_INVALID", "the MFA challenge is missing or expired")
		return
	}
	var input mfaRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "MFA request is invalid")
		return
	}
	result, err := h.Service.CompleteMFA(r.Context(), cookie.Value, input.Code)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		middleware.WriteError(w, r, http.StatusUnauthorized, "MFA_CODE_INVALID", "the authentication code is invalid or expired")
		return
	}
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "MFA_FAILED", "multi-factor authentication could not be completed")
		return
	}
	policy := auth.CookiePolicy(h.Production)
	http.SetCookie(w, &http.Cookie{Name: policy.Name, Value: result.SessionToken, Path: "/", HttpOnly: true, Secure: policy.Secure, SameSite: http.SameSiteLaxMode, MaxAge: policy.MaxAgeSeconds})
	http.SetCookie(w, &http.Cookie{Name: "netscope_mfa_challenge", Value: "", Path: "/api/v1/auth/mfa", HttpOnly: true, Secure: h.Production, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]any{"userId": result.UserID, "organizationId": result.OrganizationID}})
}
func (h Auth) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("netscope_session")
	if err == nil {
		_ = h.Service.Revoke(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "netscope_session", Value: "", Path: "/", HttpOnly: true, Secure: h.Production, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
