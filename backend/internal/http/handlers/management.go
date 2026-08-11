package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/scheduler"
	"github.com/thiagomontozo/netscope/backend/internal/scopes"
)

type Management struct {
	Commands database.Commands
	Policy   database.ControlPlane
	Registry *modules.Registry
}

func (h Management) authorized(w http.ResponseWriter, r *http.Request, permission string) bool {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), permission)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "AUTHORIZATION_CHECK_FAILED", "authorization could not be evaluated")
		return false
	}
	if !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "the required permission is not granted")
		return false
	}
	return true
}
func decode[T any](w http.ResponseWriter, r *http.Request, limit int64) (T, bool) {
	var input T
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "request body is invalid")
		return input, false
	}
	return input, true
}
func (h Management) CreateAsset(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "assets.manage") {
		return
	}
	input, ok := decode[database.AssetInput](w, r, 32<<10)
	if !ok {
		return
	}
	id, err := h.Commands.CreateAsset(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), input, middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ASSET_CREATE_FAILED", "asset fields are invalid or conflict with policy")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Management) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "assets.manage") {
		return
	}
	input, ok := decode[database.AssetInput](w, r, 32<<10)
	if !ok {
		return
	}
	err := h.Commands.UpdateAsset(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), input, middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ASSET_UPDATE_FAILED", "asset was not found or fields are invalid")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type enrollmentTokenInput struct {
	Name       string `json:"name"`
	TTLMinutes int    `json:"ttlMinutes"`
}

func (h Management) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "agents.manage") {
		return
	}
	input, ok := decode[enrollmentTokenInput](w, r, 4<<10)
	if !ok {
		return
	}
	if input.TTLMinutes < 1 || input.TTLMinutes > 60 {
		middleware.WriteError(w, r, http.StatusBadRequest, "TOKEN_TTL_INVALID", "enrollment token lifetime must be between 1 and 60 minutes")
		return
	}
	plain, digest, err := auth.NewOpaqueToken(32)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "TOKEN_CREATE_FAILED", "enrollment token could not be generated")
		return
	}
	expires := time.Now().UTC().Add(time.Duration(input.TTLMinutes) * time.Minute)
	if err = h.Commands.CreateEnrollmentToken(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), digest, input.Name, expires, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "TOKEN_CREATE_FAILED", "enrollment token could not be persisted")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"token": plain, "expiresAt": expires, "shownOnce": true}})
}
func (h Management) RevokeAgent(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "agents.manage") {
		return
	}
	if err := h.Commands.RevokeAgent(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "AGENT_NOT_FOUND", "agent was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type roleInput struct {
	Name        string      `json:"name"`
	Permissions []string    `json:"permissions"`
	RoleIDs     []domain.ID `json:"roleIds"`
}

func (h Management) CreateRole(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "users.manage") {
		return
	}
	input, ok := decode[roleInput](w, r, 16<<10)
	if !ok {
		return
	}
	id, err := h.Commands.CreateRole(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), strings.TrimSpace(input.Name), middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ROLE_CREATE_FAILED", "role name is invalid or already used")
		return
	}
	if len(input.Permissions) > 0 {
		if err = h.Commands.SetRolePermissions(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), id, input.Permissions, middleware.RequestIDFrom(r.Context())); err != nil {
			middleware.WriteError(w, r, http.StatusBadRequest, "ROLE_PERMISSION_FAILED", "role was created but permissions were invalid")
			return
		}
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Management) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "users.manage") {
		return
	}
	input, ok := decode[roleInput](w, r, 16<<10)
	if !ok {
		return
	}
	if err := h.Commands.SetRolePermissions(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), input.Permissions, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ROLE_PERMISSION_FAILED", "custom role or permissions are invalid")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "users.manage") {
		return
	}
	input, ok := decode[roleInput](w, r, 16<<10)
	if !ok {
		return
	}
	if err := h.Commands.SetUserRoles(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), input.RoleIDs, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "USER_ROLE_FAILED", "user or roles are invalid")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) DeleteAsset(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "assets.manage") {
		return
	}
	err := h.Commands.DeleteAsset(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "ASSET_DELETE_FAILED", "asset is missing or still referenced")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) CreateScope(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "scopes.manage") {
		return
	}
	input, ok := decode[database.ScopeInput](w, r, 32<<10)
	if !ok {
		return
	}
	if input.ValidFrom.IsZero() {
		input.ValidFrom = time.Now().UTC()
	}
	if !input.ValidUntil.After(input.ValidFrom) {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCOPE_VALIDITY_INVALID", "validUntil must be after validFrom")
		return
	}
	candidate := domain.AuthorizedScope{Type: domain.ScopeType(input.Type), Value: input.Value, Environment: domain.ScopeEnvironment(input.Environment)}
	normalized, err := scopes.Normalize(candidate)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCOPE_TARGET_INVALID", "scope value cannot be normalized")
		return
	}
	id, err := h.Commands.CreateScope(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), input, normalized, middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCOPE_CREATE_FAILED", "scope could not be created")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Management) ApproveScope(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "scopes.approve") {
		return
	}
	err := h.Commands.SetScopeStatus(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), "APPROVED", "scope.approved", middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "SCOPE_NOT_FOUND", "scope was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) RevokeScope(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "scopes.approve") {
		return
	}
	err := h.Commands.SetScopeStatus(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), "REVOKED", "scope.revoked", middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "SCOPE_NOT_FOUND", "scope was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type statusInput struct {
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
}

func (h Management) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "findings.manage") {
		return
	}
	input, ok := decode[statusInput](w, r, 4<<10)
	if !ok {
		return
	}
	allowed := map[string]bool{"OPEN": true, "ACKNOWLEDGED": true, "RESOLVED": true, "ACCEPTED": true, "FALSE_POSITIVE": true}
	input.Status = strings.ToUpper(input.Status)
	if !allowed[input.Status] {
		middleware.WriteError(w, r, http.StatusBadRequest, "FINDING_STATUS_INVALID", "finding status is invalid")
		return
	}
	if err := h.Commands.SetFindingStatus(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), input.Status, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "FINDING_NOT_FOUND", "finding was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "diagnostics.run") {
		return
	}
	input, ok := decode[database.ScheduleInput](w, r, 16<<10)
	if !ok {
		return
	}
	adapter, exists := h.Registry.Get(input.ModuleID)
	if !exists {
		middleware.WriteError(w, r, http.StatusBadRequest, "MODULE_UNKNOWN", "module is not registered")
		return
	}
	schedulable := map[string]bool{"network.ping": true, "network.dns": true, "network.http": true, "network.tls": true, "network.tcp": true}
	if !schedulable[input.ModuleID] {
		middleware.WriteError(w, r, http.StatusBadRequest, "MODULE_NOT_SCHEDULABLE", "only safe monitoring modules can be scheduled")
		return
	}
	if err := adapter.Validator.Validate(input.Parameters); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_PARAMETERS", err.Error())
		return
	}
	if err := scheduler.ValidateFrequency(adapter.Definition.RiskClass, time.Duration(input.FrequencySeconds)*time.Second); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCHEDULE_FREQUENCY_INVALID", err.Error())
		return
	}
	scope, scopeErr := h.Policy.GetForOrganization(r.Context(), middleware.OrganizationID(r.Context()), input.ScopeID)
	if scopeErr != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCOPE_NOT_FOUND", "scope was not found in this organization")
		return
	}
	if scope.Environment == domain.EnvironmentPublic && !h.authorized(w, r, "public_scan.run") {
		return
	}
	id, err := h.Commands.CreateSchedule(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), input, middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SCHEDULE_CREATE_FAILED", "scope or agent is invalid for this organization")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Management) SetSchedule(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "diagnostics.run") {
		return
	}
	input, ok := decode[statusInput](w, r, 4<<10)
	if !ok {
		return
	}
	if err := h.Commands.SetScheduleEnabled(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), input.Enabled, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "SCHEDULE_NOT_FOUND", "schedule was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) SetModule(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "modules.manage") {
		return
	}
	input, ok := decode[statusInput](w, r, 4<<10)
	if !ok {
		return
	}
	moduleID := chi.URLParam(r, "id")
	if _, exists := h.Registry.Get(moduleID); !exists {
		middleware.WriteError(w, r, http.StatusNotFound, "MODULE_UNKNOWN", "module is not registered")
		return
	}
	if err := h.Commands.SetModuleEnabled(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), moduleID, input.Enabled, middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "MODULE_UPDATE_FAILED", "module setting could not be updated")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h Management) CancelJob(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "diagnostics.run") {
		return
	}
	if err := h.Commands.CancelJob(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), domain.ID(chi.URLParam(r, "id")), middleware.RequestIDFrom(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_NOT_CANCELLABLE", "job is missing or already terminal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createUserInput struct {
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	RoleID   domain.ID `json:"roleId"`
}

func (h Management) CreateUser(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "users.manage") {
		return
	}
	input, ok := decode[createUserInput](w, r, 16<<10)
	if !ok {
		return
	}
	hash, err := auth.HashPassword(input.Password)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "PASSWORD_POLICY_FAILED", err.Error())
		return
	}
	id, err := h.Commands.CreateUser(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), database.UserInput{Name: input.Name, Email: input.Email, PasswordHash: hash, RoleID: input.RoleID}, middleware.RequestIDFrom(r.Context()))
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "USER_CREATE_FAILED", "user or role details are invalid")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Management) DisableUser(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r, "users.manage") {
		return
	}
	id := domain.ID(chi.URLParam(r, "id"))
	if id == middleware.UserID(r.Context()) {
		middleware.WriteError(w, r, http.StatusConflict, "SELF_DISABLE_BLOCKED", "use another administrator to disable this account")
		return
	}
	service := auth.Service{Pool: h.Commands.Pool}
	if err := service.DisableUser(r.Context(), middleware.OrganizationID(r.Context()), id); err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "user was not found in this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
