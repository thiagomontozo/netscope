package handlers

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
	"io"
	"net/http"
	"strings"
)

type Evidence struct {
	Pool    *pgxpool.Pool
	Storage storage.ObjectStorage
	Policy  interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

func (h Evidence) Raw(w http.ResponseWriter, r *http.Request) {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), "evidence.raw.read")
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "raw technical evidence permission is required")
		return
	}
	var key, contentType string
	err = h.Pool.QueryRow(r.Context(), `SELECT storage_key,content_type FROM evidence WHERE organization_id=$1 AND id=$2 AND storage_key IS NOT NULL`, middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id"))).Scan(&key, &contentType)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "EVIDENCE_NOT_FOUND", "raw evidence was not found in this organization")
		return
	}
	reader, err := h.Storage.Open(r.Context(), key)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "EVIDENCE_ARTIFACT_MISSING", "raw evidence artifact is unavailable")
		return
	}
	defer reader.Close()
	if contentType==""||strings.ContainsAny(contentType,"\r\n"){contentType="application/octet-stream"}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="netscope-evidence.bin"`)
	_, _ = io.Copy(w, reader)
}
