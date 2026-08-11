package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
)

type Investigations struct {
	Pool   *pgxpool.Pool
	Policy interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

func (h Investigations) allowed(w http.ResponseWriter, r *http.Request, permission string) bool {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), permission)
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "the required permission is not granted")
		return false
	}
	return true
}

type vantageInput struct {
	Name        string                  `json:"name"`
	AgentID     *domain.ID              `json:"agentId"`
	Site        string                  `json:"site"`
	NetworkZone string                  `json:"networkZone"`
	Environment domain.ScopeEnvironment `json:"environment"`
	Labels      map[string]string       `json:"labels"`
}

func (h Investigations) CreateVantagePoint(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "agents.manage") {
		return
	}
	in, ok := decode[vantageInput](w, r, 32<<10)
	if !ok {
		return
	}
	if strings.TrimSpace(in.Name) == "" || (in.Environment != domain.EnvironmentInternal && in.Environment != domain.EnvironmentPublic) {
		middleware.WriteError(w, r, http.StatusBadRequest, "VANTAGE_POINT_INVALID", "name and environment are required")
		return
	}
	labels, _ := json.Marshal(in.Labels)
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO vantage_points(organization_id,name,agent_id,site,network_zone,environment,labels) SELECT $1,$2,a.id,NULLIF($4,''),NULLIF($5,''),$6,$7 FROM (SELECT $3::uuid AS id) requested LEFT JOIN agents a ON a.organization_id=$1 AND a.id=requested.id WHERE $3::uuid IS NULL OR a.id IS NOT NULL RETURNING id::text`, middleware.OrganizationID(r.Context()), strings.TrimSpace(in.Name), in.AgentID, in.Site, in.NetworkZone, in.Environment, labels).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "VANTAGE_POINT_CREATE_FAILED", "vantage point or agent is invalid for this organization")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}

type serviceInput struct {
	AssetID        domain.ID `json:"assetId"`
	Protocol       string    `json:"protocol"`
	Port           int       `json:"port"`
	Name           string    `json:"name"`
	Product        string    `json:"product"`
	Version        string    `json:"version"`
	PublicExposure bool      `json:"publicExposure"`
}

func (h Investigations) CreateService(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "services.manage") {
		return
	}
	in, ok := decode[serviceInput](w, r, 16<<10)
	if !ok {
		return
	}
	if in.Port < 1 || in.Port > 65535 || strings.TrimSpace(in.Protocol) == "" || strings.TrimSpace(in.Name) == "" {
		middleware.WriteError(w, r, http.StatusBadRequest, "SERVICE_INVALID", "protocol, port and name are required")
		return
	}
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO network_services(organization_id,asset_id,protocol,port,name,product,version,public_exposure) SELECT $1,a.id,lower($3),$4,$5,NULLIF($6,''),NULLIF($7,''),$8 FROM assets a WHERE a.organization_id=$1 AND a.id=$2 RETURNING id::text`, middleware.OrganizationID(r.Context()), in.AssetID, in.Protocol, in.Port, in.Name, in.Product, in.Version, in.PublicExposure).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "SERVICE_CREATE_FAILED", "service or asset is invalid for this organization")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}

type diagnosticRunInput struct {
	AssetID   domain.ID  `json:"assetId"`
	ServiceID *domain.ID `json:"serviceId"`
	Profile   string     `json:"profile"`
	Summary   string     `json:"summary"`
}

func (h Investigations) CreateDiagnosticRun(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "diagnostics.run") {
		return
	}
	in, ok := decode[diagnosticRunInput](w, r, 16<<10)
	if !ok {
		return
	}
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO diagnostic_runs(organization_id,asset_id,service_id,requested_by,profile_id,status,summary) SELECT $1,a.id,s.id,$4,p.id,'PENDING',$6 FROM assets a JOIN diagnostic_profiles p ON p.id=$5 AND p.enabled LEFT JOIN network_services s ON s.organization_id=a.organization_id AND s.asset_id=a.id AND s.id=$3 WHERE a.organization_id=$1 AND a.id=$2 AND ($3::uuid IS NULL OR s.id IS NOT NULL) RETURNING id::text`, middleware.OrganizationID(r.Context()), in.AssetID, in.ServiceID, middleware.UserID(r.Context()), in.Profile, in.Summary).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "DIAGNOSTIC_RUN_INVALID", "asset, service or safe diagnostic profile is invalid")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}

type incidentInput struct {
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       string     `json:"severity"`
	StartedAt      *time.Time `json:"startedAt"`
	PrimaryAssetID *domain.ID `json:"primaryAssetId"`
	AssignedTo     *domain.ID `json:"assignedTo"`
}

func (h Investigations) CreateIncident(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "incidents.manage") {
		return
	}
	in, ok := decode[incidentInput](w, r, 32<<10)
	if !ok {
		return
	}
	if strings.TrimSpace(in.Title) == "" {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_INVALID", "incident title is required")
		return
	}
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO incidents(organization_id,title,description,severity,started_at,created_by,assigned_to,primary_asset_id) SELECT $1,$2,$3,NULLIF($4,''),$5,$6,u.id,a.id FROM (SELECT 1) x LEFT JOIN users u ON u.organization_id=$1 AND u.id=$7 LEFT JOIN assets a ON a.organization_id=$1 AND a.id=$8 WHERE ($7::uuid IS NULL OR u.id IS NOT NULL) AND ($8::uuid IS NULL OR a.id IS NOT NULL) RETURNING id::text`, middleware.OrganizationID(r.Context()), strings.TrimSpace(in.Title), in.Description, in.Severity, in.StartedAt, middleware.UserID(r.Context()), in.AssignedTo, in.PrimaryAssetID).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_CREATE_FAILED", "incident relationships are invalid for this organization")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}

type incidentEventInput struct {
	EventType   string                  `json:"eventType"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	Status      domain.NormalizedStatus `json:"status"`
	Confidence  domain.Confidence       `json:"confidence"`
	SourceType  string                  `json:"sourceType"`
	SourceID    string                  `json:"sourceId"`
	OccurredAt  time.Time               `json:"occurredAt"`
}

func (h Investigations) AddIncidentEvent(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "incidents.manage") {
		return
	}
	in, ok := decode[incidentEventInput](w, r, 32<<10)
	if !ok {
		return
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO incident_events(organization_id,incident_id,event_type,title,description,status,confidence,source_type,source_id,occurred_at,created_by) SELECT $1,i.id,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11 FROM incidents i WHERE i.organization_id=$1 AND i.id=$2 RETURNING id::text`, middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id")), in.EventType, in.Title, in.Description, in.Status, in.Confidence, in.SourceType, in.SourceID, in.OccurredAt, middleware.UserID(r.Context())).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_EVENT_INVALID", "incident event is invalid")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}

type incidentEvidenceInput struct {
	EvidenceID domain.ID                   `json:"evidenceId"`
	Role       domain.IncidentEvidenceRole `json:"role"`
	Rationale  string                      `json:"rationale"`
}

type incidentLinkInput struct {
	LinkType string    `json:"linkType"`
	LinkedID domain.ID `json:"linkedId"`
}

func (h Investigations) AttachIncidentLink(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "incidents.manage") {
		return
	}
	in, ok := decode[incidentLinkInput](w, r, 16<<10)
	if !ok {
		return
	}
	tables := map[string]string{
		"OBSERVATION":    "observations",
		"FINDING":        "findings",
		"DIAGNOSTIC_RUN": "diagnostic_runs",
		"JOB":            "analysis_jobs",
		"AGENT":          "agents",
		"ASSET":          "assets",
		"SERVICE":        "network_services",
	}
	table, exists := tables[in.LinkType]
	if !exists || in.LinkedID == "" {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_LINK_INVALID", "incident link type or identity is invalid")
		return
	}
	// table is selected only from the fixed allowlist above; no client value is interpolated.
	query := `INSERT INTO incident_links(incident_id,organization_id,link_type,linked_id) SELECT i.id,$1,$3,x.id FROM incidents i JOIN ` + table + ` x ON x.organization_id=i.organization_id AND x.id=$4 WHERE i.organization_id=$1 AND i.id=$2 ON CONFLICT(incident_id,link_type,linked_id) DO UPDATE SET created_at=incident_links.created_at`
	tag, err := h.Pool.Exec(r.Context(), query, middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id")), in.LinkType, in.LinkedID)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_LINK_INVALID", "incident or linked record is invalid for this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h Investigations) AttachIncidentEvidence(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "incidents.manage") {
		return
	}
	in, ok := decode[incidentEvidenceInput](w, r, 16<<10)
	if !ok {
		return
	}
	allowed := map[domain.IncidentEvidenceRole]bool{domain.EvidenceKey: true, domain.EvidenceSupporting: true, domain.EvidenceContext: true}
	if !allowed[in.Role] {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_EVIDENCE_ROLE_INVALID", "evidence role is invalid")
		return
	}
	tag, err := h.Pool.Exec(r.Context(), `INSERT INTO incident_evidence(incident_id,organization_id,evidence_id,role,rationale,added_by) SELECT i.id,$1,e.id,$4,$5,$6 FROM incidents i JOIN evidence e ON e.organization_id=i.organization_id WHERE i.organization_id=$1 AND i.id=$2 AND e.id=$3 ON CONFLICT(incident_id,evidence_id) DO UPDATE SET role=excluded.role,rationale=excluded.rationale`, middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id")), in.EvidenceID, in.Role, in.Rationale, middleware.UserID(r.Context()))
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_EVIDENCE_INVALID", "incident or evidence is invalid for this organization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h Investigations) IncidentWorkspace(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "incidents.read") {
		return
	}
	var data []byte
	err := h.Pool.QueryRow(r.Context(), `SELECT jsonb_build_object('incident',to_jsonb(i),'timeline',coalesce((SELECT jsonb_agg(to_jsonb(ev) ORDER BY ev.occurred_at,ev.id) FROM incident_events ev WHERE ev.organization_id=i.organization_id AND ev.incident_id=i.id),'[]'::jsonb),'evidence',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.added_at) FROM (SELECT ie.role,ie.rationale,ie.added_at,e.id,e.summary,e.source,e.module_id,e.agent_id,e.vantage_point_id,e.checksum,e.size_bytes,e.content_type FROM incident_evidence ie JOIN evidence e ON e.organization_id=ie.organization_id AND e.id=ie.evidence_id WHERE ie.organization_id=i.organization_id AND ie.incident_id=i.id) x),'[]'::jsonb),'links',coalesce((SELECT jsonb_agg(to_jsonb(l)) FROM incident_links l WHERE l.organization_id=i.organization_id AND l.incident_id=i.id),'[]'::jsonb)) FROM incidents i WHERE i.organization_id=$1 AND i.id=$2`, middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id"))).Scan(&data)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "INCIDENT_NOT_FOUND", "incident was not found in this organization")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]jsonRaw{"data": jsonRaw(data)})
}

func (h Investigations) CreateIncidentEvidenceReport(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "reports.create") {
		return
	}
	incidentID := domain.ID(chi.URLParam(r, "id"))
	var id domain.ID
	err := h.Pool.QueryRow(r.Context(), `INSERT INTO incident_evidence_reports(organization_id,incident_id,status,confidence,summary,known_limitations,suggested_actions,created_by,completed_at) SELECT i.organization_id,i.id,'COMPLETED',CASE WHEN count(ie.evidence_id)>=2 THEN 'MEDIUM'::confidence_level ELSE 'LOW'::confidence_level END,'Incident evidence report for '||i.title,CASE WHEN i.root_cause_status IN ('UNKNOWN','INCONCLUSIVE') THEN 'Root cause has not been confirmed. Available evidence may be incomplete or vantage-specific.' ELSE 'The report reflects only evidence currently linked to this incident.' END,'Review key evidence, compare affected vantage points, and run only authorized diagnostics needed to reduce uncertainty.',$3,now() FROM incidents i LEFT JOIN incident_evidence ie ON ie.organization_id=i.organization_id AND ie.incident_id=i.id WHERE i.organization_id=$1 AND i.id=$2 GROUP BY i.id RETURNING id::text`, middleware.OrganizationID(r.Context()), incidentID, middleware.UserID(r.Context())).Scan(&id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "INCIDENT_REPORT_FAILED", "incident evidence report could not be created")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]domain.ID{"id": id}})
}
