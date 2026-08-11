package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thiagomontozo/netscope/backend/internal/agents"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
)

type heartbeatRequest struct {
	ProtocolVersion  string         `json:"protocolVersion"`
	AgentID          domain.ID      `json:"agentId"`
	AgentVersion     string         `json:"agentVersion"`
	Timestamp        time.Time      `json:"timestamp"`
	Hostname         string         `json:"hostname"`
	OS               string         `json:"os"`
	Architecture     string         `json:"architecture"`
	Status           string         `json:"status"`
	RunningJobs      int            `json:"runningJobs"`
	AvailableSlots   int            `json:"availableSlots"`
	CapabilitiesHash string         `json:"capabilitiesHash"`
	HealthSummary    map[string]any `json:"healthSummary"`
	LastJobResult    *struct {
		JobID       domain.ID `json:"jobId"`
		Status      string    `json:"status"`
		CompletedAt time.Time `json:"completedAt"`
	} `json:"lastJobResult,omitempty"`
}

type capabilityModule struct {
	ModuleID       string             `json:"moduleId"`
	CapabilityID   string             `json:"capabilityId"`
	Available      bool               `json:"available"`
	Implementation string             `json:"implementation"`
	ModuleVersion  string             `json:"moduleVersion"`
	RiskClasses    []domain.RiskClass `json:"riskClasses"`
}
type capabilityTool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Available bool   `json:"available"`
}
type capabilityRequest struct {
	ProtocolVersion      string             `json:"protocolVersion"`
	AgentID              domain.ID          `json:"agentId"`
	Platform             string             `json:"platform"`
	Modules              []capabilityModule `json:"modules"`
	ExternalTools        []capabilityTool   `json:"externalTools"`
	NetworkCapabilities  []string           `json:"networkCapabilities"`
	ArtifactCapabilities []string           `json:"artifactCapabilities"`
}

func (h Agent) Capabilities(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[capabilityRequest](w, r, 256<<10)
	if !ok {
		return
	}
	if input.AgentID != middleware.AgentID(r.Context()) || agents.RequireCompatible(input.ProtocolVersion) != nil || len(input.Modules) > 200 || len(input.ExternalTools) > 100 {
		middleware.WriteError(w, r, http.StatusBadRequest, "CAPABILITY_MANIFEST_INVALID", "capability manifest is invalid or incompatible")
		return
	}
	manifest, err := json.Marshal(input)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "CAPABILITY_MANIFEST_INVALID", "capability manifest could not be encoded")
		return
	}
	digest := sha256.Sum256(manifest)
	available := make([]string, 0, len(input.Modules))
	for _, module := range input.Modules {
		if module.Available {
			if module.CapabilityID != "" {
				available = append(available, module.CapabilityID)
			} else {
				available = append(available, module.ModuleID)
			}
		}
	}
	capabilities, _ := json.Marshal(available)
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `UPDATE agents SET capabilities_manifest=$3,capabilities_hash=$4,capabilities=$5,protocol_version=$6,compatibility_status=$7,last_seen_at=now() WHERE organization_id=$1 AND id=$2 AND status<>'REVOKED'`, middleware.OrganizationID(r.Context()), input.AgentID, manifest, hex.EncodeToString(digest[:]), capabilities, input.ProtocolVersion, agents.Compatibility(input.ProtocolVersion))
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusUnauthorized, "CAPABILITY_MANIFEST_REJECTED", "agent is no longer active")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]string{"capabilitiesHash": hex.EncodeToString(digest[:])}})
}

func (h Agent) Cancellation(w http.ResponseWriter, r *http.Request) {
	jobID := domain.ID(chi.URLParam(r, "id"))
	var status string
	var requestedAt *time.Time
	err := h.Enrollment.Pool.QueryRow(r.Context(), `SELECT j.status,c.requested_at FROM analysis_jobs j LEFT JOIN job_cancellation_requests c ON c.job_id=j.id AND c.organization_id=j.organization_id WHERE j.organization_id=$1 AND j.agent_id=$2 AND j.id=$3`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), jobID).Scan(&status, &requestedAt)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "JOB_NOT_FOUND", "job is not assigned to this agent")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]any{"protocolVersion": domain.AgentProtocolVersion, "jobId": jobID, "cancellationRequested": requestedAt != nil, "requestedAt": requestedAt, "jobStatus": status}})
}

type evidenceRequest struct {
	ProtocolVersion string        `json:"protocolVersion"`
	JobID           domain.ID     `json:"jobId"`
	AgentID         domain.ID     `json:"agentId"`
	Evidence        agentEvidence `json:"evidence"`
}

func (h Agent) Evidence(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[evidenceRequest](w, r, 2<<20)
	if !ok {
		return
	}
	if agents.RequireCompatible(in.ProtocolVersion) != nil || in.AgentID != middleware.AgentID(r.Context()) || in.Evidence.EvidenceID == "" || len(in.Evidence.SHA256) != 64 || in.Evidence.SizeBytes < 0 || !validJSONObject(in.Evidence.StructuredData) || len(in.Evidence.Summary) > 4000 {
		middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_MANIFEST_INVALID", "evidence manifest is invalid")
		return
	}
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `INSERT INTO evidence(id,organization_id,job_id,source,content_type,summary,structured_data,checksum,module_id,agent_id,vantage_point_id,artifact_kind,size_bytes,observed_at) SELECT $4,j.organization_id,j.id,$5,$6,$7,$8,$9,j.module_id,j.agent_id,j.vantage_point_id,NULLIF($10,''),$11,now() FROM analysis_jobs j WHERE j.organization_id=$1 AND j.agent_id=$2 AND j.id=$3 AND j.status IN ('ASSIGNED','RUNNING') ON CONFLICT(id) DO NOTHING`, middleware.OrganizationID(r.Context()), in.AgentID, in.JobID, in.Evidence.EvidenceID, in.Evidence.Source, in.Evidence.ContentType, in.Evidence.Summary, in.Evidence.StructuredData, in.Evidence.SHA256, in.Evidence.ArtifactKind, in.Evidence.SizeBytes)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_MANIFEST_INVALID", "evidence metadata could not be stored")
		return
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = h.Enrollment.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM evidence WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND job_id=$4 AND checksum=$5)`, middleware.OrganizationID(r.Context()), in.AgentID, in.Evidence.EvidenceID, in.JobID, in.Evidence.SHA256).Scan(&exists)
		if !exists {
			middleware.WriteError(w, r, http.StatusConflict, "EVIDENCE_IDENTITY_CONFLICT", "evidence identity already exists with different content or the job cannot accept evidence")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
