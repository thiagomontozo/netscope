package handlers

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/reports"
	"io"
	"net/http"
	"strings"
)

type Reports struct {
	Service reports.Service
	Policy  interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}
type reportInput struct {
	Type  reports.Type `json:"type"`
	Title string       `json:"title"`
}

func (h Reports) allowed(w http.ResponseWriter, r *http.Request, permission string) bool {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), permission)
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "the required report permission is not granted")
		return false
	}
	return true
}
func (h Reports) Create(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "reports.create") {
		return
	}
	input, ok := decode[reportInput](w, r, 8<<10)
	if !ok {
		return
	}
	allowed := map[reports.Type]bool{reports.NetworkHealth: true, reports.AssetSecurity: true, reports.Vulnerability: true, reports.PublicExposure: true, reports.PCAPAnalysis: true, reports.ExecutiveSummary: true}
	if !allowed[input.Type] || strings.TrimSpace(input.Title) == "" {
		middleware.WriteError(w, r, http.StatusBadRequest, "REPORT_REQUEST_INVALID", "report type and title are required")
		return
	}
	id, err := h.Service.Create(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), input.Type, input.Title)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "REPORT_CREATE_FAILED", "report could not be generated")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
func (h Reports) Download(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "reports.read") {
		return
	}
	reader, title, err := h.Service.Open(r.Context(), middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id")))
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "REPORT_NOT_FOUND", "report was not found in this organization")
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netscope-report.html"`)
	w.Header().Set("X-NetScope-Report-Title", title)
	_, _ = io.Copy(w, reader)
}
