package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/agents"
	"github.com/thiagomontozo/netscope/backend/internal/artifacts"
	"github.com/thiagomontozo/netscope/backend/internal/auth"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/http/handlers"
	appmw "github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/reports"
	"github.com/thiagomontozo/netscope/backend/internal/scanguard"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
	"github.com/thiagomontozo/netscope/backend/internal/vulnerabilities"
	"log/slog"
	"net/http"
	"time"
)

type Runtime struct {
	Store                    database.ControlPlane
	Auth                     auth.Service
	Enrollment               agents.EnrollmentService
	Storage                  storage.ObjectStorage
	NVD                      vulnerabilities.VulnerabilityEnrichmentProvider
	KEV                      vulnerabilities.KnownExploitedProvider
	Production               bool
	MaxConcurrent            int
	JobSigner                agents.JobEnvelopeSigner
	RequireSignedJobs        bool
	ArtifactTokens           artifacts.TokenManager
	MaxArtifactDownloadBytes int64
	MaxArtifactUploadBytes   int64
	ArtifactTempDir          string
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
	r.Route("/api/v1", func(api chi.Router) {
		api.Use(appmw.SessionIdentity(runtime.Store))
		api.Use(appmw.RequireCSRF)
		api.Post("/auth/logout", authHandler.Logout)
		api.Post("/auth/logout-all", authHandler.LogoutAll)
		api.Post("/auth/mfa/setup", authHandler.BeginMFASetup)
		api.Post("/auth/mfa/confirm", authHandler.ConfirmMFASetup)
		moduleHandler := handlers.Modules{Registry: registry, Policy: runtime.Store}
		api.Get("/modules", moduleHandler.List)
		jobHandler := handlers.Jobs{Registry: registry, Guard: scanguard.Guard{Permissions: runtime.Store, Agents: runtime.Store, Policies: runtime.Store}, Scopes: runtime.Store, Store: runtime.Store, MaxConcurrent: runtime.MaxConcurrent}
		api.Post("/jobs", jobHandler.Create)
		management := handlers.Management{Commands: database.Commands{Pool: runtime.Store.Pool}, Policy: runtime.Store, Registry: registry}
		investigations := handlers.Investigations{Pool: runtime.Store.Pool, Policy: runtime.Store}
		api.Post("/vantage-points", investigations.CreateVantagePoint)
		api.Post("/services", investigations.CreateService)
		api.Post("/diagnostic-runs", investigations.CreateDiagnosticRun)
		api.Post("/incidents", investigations.CreateIncident)
		api.Get("/incidents/{id}/workspace", investigations.IncidentWorkspace)
		api.Post("/incidents/{id}/events", investigations.AddIncidentEvent)
		api.Post("/incidents/{id}/links", investigations.AttachIncidentLink)
		api.Post("/incidents/{id}/evidence", investigations.AttachIncidentEvidence)
		api.Post("/incidents/{id}/evidence-report", investigations.CreateIncidentEvidenceReport)
		api.Post("/assets", management.CreateAsset)
		api.Put("/assets/{id}", management.UpdateAsset)
		api.Delete("/assets/{id}", management.DeleteAsset)
		api.Post("/scopes", management.CreateScope)
		api.Post("/scopes/{id}/approve", management.ApproveScope)
		api.Post("/scopes/{id}/revoke", management.RevokeScope)
		api.Patch("/findings/{id}", management.UpdateFinding)
		api.Post("/schedules", management.CreateSchedule)
		api.Patch("/schedules/{id}", management.SetSchedule)
		api.Patch("/modules/{id}", management.SetModule)
		api.Post("/jobs/{id}/cancel", management.CancelJob)
		api.Post("/users", management.CreateUser)
		api.Post("/users/{id}/disable", management.DisableUser)
		api.Post("/agents/enrollment-tokens", management.CreateEnrollmentToken)
		api.Post("/agents/{id}/revoke", management.RevokeAgent)
		api.Post("/roles", management.CreateRole)
		api.Put("/roles/{id}/permissions", management.SetRolePermissions)
		api.Put("/users/{id}/roles", management.SetUserRoles)
		reportHandler := handlers.Reports{Service: reports.Service{Pool: runtime.Store.Pool, Storage: runtime.Storage}, Policy: runtime.Store}
		api.Post("/reports", reportHandler.Create)
		api.Get("/reports/{id}/download", reportHandler.Download)
		pcapHandler := handlers.PCAP{Pool: runtime.Store.Pool, Storage: runtime.Storage, Policy: runtime.Store}
		api.Post("/pcap", pcapHandler.Upload)
		api.Get("/pcap/{id}/download", pcapHandler.Download)
		api.Delete("/pcap/{id}", pcapHandler.Delete)
		evidenceHandler := handlers.Evidence{Pool: runtime.Store.Pool, Storage: runtime.Storage, Policy: runtime.Store}
		api.Get("/evidence/{id}/raw", evidenceHandler.Raw)
		enrichmentHandler := handlers.Enrichment{Pool: runtime.Store.Pool, NVD: runtime.NVD, KEV: runtime.KEV, Policy: runtime.Store}
		api.Post("/vulnerabilities/{id}/enrich", enrichmentHandler.Run)
		resources := database.Resources{Pool: runtime.Store.Pool}
		for _, resource := range []string{"users", "roles", "permissions", "assets", "services", "public-exposure", "scopes", "agents", "vantage-points", "jobs", "artifacts", "diagnostic-runs", "schedules", "observations", "findings", "evidence", "incidents", "incident-events", "incident-reports", "route-snapshots", "route-comparisons", "monitor-history", "baselines", "changes", "vulnerabilities", "traffic", "pcap", "reports", "notifications", "audit"} {
			path := "/" + resource
			handler := handlers.Resources{Store: resources, Resource: resource, Policy: runtime.Store}
			api.Get(path, handler.List)
			api.Get(path+"/{id}", handler.Get)
		}
		api.Get("/events", events)
	})
	agentHandler := handlers.Agent{Enrollment: runtime.Enrollment, Signer: runtime.JobSigner, RequireSignedJobs: runtime.RequireSignedJobs, Rotation: agents.RotationService{Pool: runtime.Store.Pool, CA: runtime.Enrollment.CA, Policy: agents.DefaultCertificatePolicy()}}
	r.With(appmw.RateLimit(10, time.Minute)).Post("/agent/v1/enroll", agentHandler.Enroll)
	r.Route("/agent/v1", func(agent chi.Router) {
		agent.Use(appmw.AgentIdentity(runtime.Store))
		h := agentHandler
		agent.Post("/heartbeat", h.Heartbeat)
		agent.Post("/capabilities", h.Capabilities)
		agent.Post("/evidence", h.Evidence)
		agent.With(appmw.RateLimit(6, time.Minute)).Post("/identity/rotate", h.RotateIdentity)
		agent.With(appmw.RateLimit(12, time.Minute)).Post("/identity/rotate/confirm", h.ConfirmIdentityRotation)
		agent.MethodFunc(http.MethodGet, "/jobs/next", h.NextJob)
		agent.MethodFunc(http.MethodPost, "/jobs/next", h.NextJob)
		agent.Post("/jobs/{id}/start", h.StartJob)
		agent.Post("/jobs/{id}/result", h.Result)
		agent.Post("/jobs/{id}/fail", h.Fail)
		agent.Get("/jobs/{id}/cancellation", h.Cancellation)
		artifactHandler := handlers.AgentArtifacts{Pool: runtime.Store.Pool, Storage: runtime.Storage, Tokens: runtime.ArtifactTokens, MaxDownloadBytes: runtime.MaxArtifactDownloadBytes, MaxUploadBytes: runtime.MaxArtifactUploadBytes, TempDir: runtime.ArtifactTempDir}
		agent.Post("/artifacts", artifactHandler.Create)
		agent.With(appmw.RateLimit(120, time.Minute)).Post("/artifacts/{id}/authorize", artifactHandler.Authorize)
		agent.Get("/artifacts/{id}/content", artifactHandler.Download)
		agent.Put("/artifacts/{id}/content", artifactHandler.Upload)
	})
	return r
}
func events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte("event: ready\ndata: {\"status\":\"connected\"}\n\n"))
}
