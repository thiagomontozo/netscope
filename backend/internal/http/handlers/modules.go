package handlers

import (
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"net/http"
)

type Modules struct{ Registry *modules.Registry }

func (h Modules) List(w http.ResponseWriter, r *http.Request) {
	middleware.JSON(w, http.StatusOK, map[string]any{"data": h.Registry.List()})
}
