package handlers

import (
	"context"
	"encoding/json"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/scanguard"
	"net/http"
	"time"
)

type ScopeReader interface {
	GetForOrganization(context.Context, domain.ID, domain.ID) (domain.AuthorizedScope, error)
}
type JobWriter interface {
	CreateAuthorized(context.Context, domain.AnalysisJob, string) error
}
type Jobs struct {
	Registry      *modules.Registry
	Guard         scanguard.Guard
	Scopes        ScopeReader
	Store         JobWriter
	MaxConcurrent int
}
type createJobRequest struct {
	ModuleID   string          `json:"moduleId"`
	ScopeID    domain.ID       `json:"scopeId"`
	AssetID    domain.ID       `json:"assetId"`
	AgentID    domain.ID       `json:"agentId"`
	Parameters json.RawMessage `json:"parameters"`
}

func (h Jobs) Create(w http.ResponseWriter, r *http.Request) {
	var input createJobRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "request body is invalid")
		return
	}
	org := middleware.OrganizationID(r.Context())
	user := middleware.UserID(r.Context())
	adapter, ok := h.Registry.Get(input.ModuleID)
	if !ok {
		middleware.WriteError(w, r, http.StatusBadRequest, "MODULE_UNKNOWN", "module is not registered")
		return
	}
	scope, err := h.Scopes.GetForOrganization(r.Context(), org, input.ScopeID)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "SCOPE_NOT_FOUND", "scope was not found in this organization")
		return
	}
	now := time.Now().UTC()
	decision, err := h.Guard.Authorize(r.Context(), scanguard.Request{OrganizationID: org, UserID: user, AgentID: input.AgentID, Scope: scope, Adapter: adapter, Parameters: input.Parameters, Now: now, MaxConcurrent: h.MaxConcurrent})
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "AUTHORIZATION_CHECK_FAILED", "the authorization decision could not be completed")
		return
	}
	if !decision.Allowed {
		middleware.WriteError(w, r, http.StatusForbidden, decision.Code, decision.Reason)
		return
	}
	job := domain.AnalysisJob{ID: domain.ID(newID()), OrganizationID: org, ModuleID: input.ModuleID, AssetID: input.AssetID, ScopeID: input.ScopeID, AgentID: input.AgentID, RequestedBy: user, Parameters: input.Parameters, RiskClass: adapter.Definition.RiskClass, Status: domain.JobQueued, CreatedAt: now, TimeoutAt: decision.TimeoutAt}
	if err := h.Store.CreateAuthorized(r.Context(), job, decision.NormalizedTarget); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_CREATE_FAILED", "the job could not be created")
		return
	}
	middleware.JSON(w, http.StatusAccepted, map[string]any{"data": job})
}
func newID() string { return time.Now().UTC().Format("20060102T150405.000000000") }
