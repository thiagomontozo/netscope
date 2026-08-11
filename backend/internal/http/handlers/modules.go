package handlers

import (
	"context"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"net/http"
)

type Modules struct {
	Registry *modules.Registry
	Policy   interface {
		ModuleEnabled(context.Context, domain.ID, string) (bool, error)
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

func (h Modules) List(w http.ResponseWriter, r *http.Request) {
	allowed, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), "modules.read")
	if err != nil || !allowed {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "module read permission is not granted")
		return
	}
	definitions := h.Registry.List()
	for index := range definitions {
		enabled, err := h.Policy.ModuleEnabled(r.Context(), middleware.OrganizationID(r.Context()), definitions[index].ID)
		if err != nil {
			middleware.WriteError(w, r, http.StatusInternalServerError, "MODULE_LIST_FAILED", "module settings could not be loaded")
			return
		}
		definitions[index].Enabled = enabled
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": definitions})
}
