package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
)

type Resources struct {
	Store    database.Resources
	Resource string
	Policy   interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

var resourcePermissions = map[string]string{"users": "users.read", "roles": "users.read", "permissions": "users.read", "assets": "assets.read", "services": "services.read", "public-exposure": "services.read", "scopes": "scopes.read", "agents": "agents.read", "vantage-points": "agents.read", "jobs": "diagnostics.read", "diagnostic-runs": "diagnostics.read", "schedules": "diagnostics.read", "observations": "diagnostics.read", "findings": "findings.read", "evidence": "findings.read", "incidents": "incidents.read", "incident-events": "incidents.read", "incident-reports": "reports.read", "route-snapshots": "diagnostics.read", "route-comparisons": "diagnostics.read", "monitor-history": "diagnostics.read", "baselines": "diagnostics.read", "changes": "diagnostics.read", "vulnerabilities": "vulnerability.read", "traffic": "traffic.read", "pcap": "pcap.read", "reports": "reports.read", "audit": "audit.read"}

func (h Resources) allowed(w http.ResponseWriter, r *http.Request) bool {
	permission := resourcePermissions[h.Resource]
	if permission == "" {
		return true
	}
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), permission)
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "the required read permission is not granted")
		return false
	}
	return true
}

func (h Resources) List(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	data, err := h.Store.List(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), h.Resource, limit, offset)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESOURCE_LIST_FAILED", "the requested records could not be loaded")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]jsonRaw{"data": jsonRaw(data)})
}
func (h Resources) Get(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r) {
		return
	}
	id := domain.ID(chi.URLParam(r, "id"))
	data, err := h.Store.Get(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), h.Resource, id)
	if database.IsNotFound(err) {
		middleware.WriteError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "the requested record was not found in this organization")
		return
	}
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESOURCE_READ_FAILED", "the requested record could not be loaded")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]jsonRaw{"data": jsonRaw(data)})
}

type jsonRaw []byte

func (j jsonRaw) MarshalJSON() ([]byte, error) { return j, nil }
