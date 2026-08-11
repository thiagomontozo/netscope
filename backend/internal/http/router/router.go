package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/http/handlers"
	appmw "github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/scanguard"
	"log/slog"
	"net/http"
)

type Runtime struct {
	Store         database.ControlPlane
	Auth          auth.Service
	Production    bool
	MaxConcurrent int
}

func New(logger *slog.Logger, registry *modules.Registry, runtime Runtime) http.Handler {
	r := chi.NewRouter()
	r.Use(appmw.RequestID, middleware.RealIP, middleware.Recoverer, appmw.AccessLog(logger))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		appmw.JSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})
	authHandler := handlers.Auth{Service: runtime.Auth, Production: runtime.Production}
	r.Post("/api/v1/auth/login", authHandler.Login)
	r.Post("/api/v1/auth/mfa", authHandler.MFA)
	r.Post("/api/v1/auth/logout", authHandler.Logout)
	r.Route("/api/v1", func(api chi.Router) {
		api.Use(appmw.SessionIdentity(runtime.Store))
		moduleHandler := handlers.Modules{Registry: registry}
		api.Get("/modules", moduleHandler.List)
		jobHandler := handlers.Jobs{Registry: registry, Guard: scanguard.Guard{Permissions: runtime.Store, Agents: runtime.Store, Policies: runtime.Store}, Scopes: runtime.Store, Store: runtime.Store, MaxConcurrent: runtime.MaxConcurrent}
		api.Post("/jobs", jobHandler.Create)
		for _, resource := range []string{"users", "roles", "permissions", "assets", "scopes", "agents", "jobs", "schedules", "observations", "findings", "evidence", "vulnerabilities", "traffic", "pcap", "reports", "notifications", "audit"} {
			path := "/" + resource
			api.Get(path, notImplemented(resource))
		}
		api.Get("/events", events)
	})
	r.Route("/agent/v1", func(agent chi.Router) {
		agent.Use(appmw.AgentIdentity)
		h := handlers.Agent{}
		agent.Post("/heartbeat", h.Heartbeat)
		agent.MethodFunc(http.MethodGet, "/jobs/next", h.NextJob)
		agent.MethodFunc(http.MethodPost, "/jobs/next", h.NextJob)
		agent.Post("/jobs/{id}/start", h.JobState)
		agent.Post("/jobs/{id}/result", h.JobState)
		agent.Post("/jobs/{id}/fail", h.JobState)
	})
	return r
}
func notImplemented(resource string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appmw.JSON(w, http.StatusOK, map[string]any{"data": []any{}, "meta": map[string]string{"resource": resource, "status": "foundation"}})
	}
}
func events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte("event: ready\ndata: {\"status\":\"connected\"}\n\n"))
}
