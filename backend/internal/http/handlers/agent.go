package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/netscope/backend/internal/agents"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
)

type Agent struct{ Enrollment agents.EnrollmentService }

func (h Agent) Enroll(w http.ResponseWriter, r *http.Request) {
	var input agents.EnrollmentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ENROLLMENT_REQUEST_INVALID", "enrollment request is invalid")
		return
	}
	result, err := h.Enrollment.Enroll(r.Context(), input)
	if err != nil {
		middleware.WriteError(w, r, http.StatusUnauthorized, "ENROLLMENT_FAILED", err.Error())
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": result})
}
func (h Agent) Heartbeat(w http.ResponseWriter, r *http.Request) {
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `UPDATE agents SET last_seen_at=now(),status='ONLINE' WHERE organization_id=$1 AND id=$2 AND status<>'REVOKED'`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()))
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusUnauthorized, "HEARTBEAT_REJECTED", "agent is no longer active")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "accepted"}})
}
func (h Agent) NextJob(w http.ResponseWriter, r *http.Request) {
	tx, err := h.Enrollment.Pool.Begin(r.Context())
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_POLL_FAILED", "job polling failed")
		return
	}
	defer tx.Rollback(r.Context())
	var envelope domain.JobEnvelope
	var timeout time.Time
	err = tx.QueryRow(r.Context(), `SELECT id::text,module_id,scope_id::text,normalized_target,parameters,risk_class,timeout_at FROM analysis_jobs WHERE organization_id=$1 AND agent_id=$2 AND status='QUEUED' AND timeout_at>now() ORDER BY queued_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context())).Scan(&envelope.JobID, &envelope.ModuleID, &envelope.ScopeID, &envelope.TargetReference, &envelope.Parameters, &envelope.RiskClass, &timeout)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_POLL_FAILED", "job polling failed")
		return
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_ENVELOPE_FAILED", "job nonce could not be generated")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(5 * time.Minute)
	if timeout.Before(expires) {
		expires = timeout
	}
	envelope.OrganizationID = middleware.OrganizationID(r.Context())
	envelope.AgentID = middleware.AgentID(r.Context())
	envelope.IssuedAt = now
	envelope.ExpiresAt = expires
	envelope.Nonce = hex.EncodeToString(nonce)
	tag, err := tx.Exec(r.Context(), `UPDATE analysis_jobs SET status='ASSIGNED',status_version=status_version+1 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='QUEUED'`, envelope.OrganizationID, envelope.AgentID, envelope.JobID)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_ASSIGNMENT_RACE", "job assignment changed concurrently")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_ASSIGNMENT_FAILED", "job assignment could not be committed")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": envelope})
}
func (h Agent) StartJob(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, "ASSIGNED", "RUNNING", "job.started")
}
func (h Agent) transition(w http.ResponseWriter, r *http.Request, from, to, event string) {
	id := domain.ID(chi.URLParam(r, "id"))
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `WITH changed AS (UPDATE analysis_jobs SET status=$4,started_at=CASE WHEN $4='RUNNING' THEN now() ELSE started_at END,completed_at=CASE WHEN $4 IN ('SUCCEEDED','FAILED') THEN now() ELSE completed_at END,status_version=status_version+1 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status=$5 RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome) SELECT $1,$2,$6,'job',id::text,'success' FROM changed`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), id, to, from, event)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job state transition was rejected")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type agentObservation struct {
	AssetID         *domain.ID              `json:"assetId"`
	Category        string                  `json:"category"`
	Status          domain.NormalizedStatus `json:"status"`
	Severity        string                  `json:"severity"`
	Confidence      domain.Confidence       `json:"confidence"`
	Title           string                  `json:"title"`
	Summary         string                  `json:"summary"`
	Meaning         string                  `json:"meaning"`
	Impact          string                  `json:"impact"`
	SuggestedAction string                  `json:"suggestedAction"`
	ObservedAt      time.Time               `json:"observedAt"`
}
type agentEvidence struct {
	Source         string          `json:"source"`
	ContentType    string          `json:"contentType"`
	Summary        string          `json:"summary"`
	StructuredData json.RawMessage `json:"structuredData"`
	Checksum       string          `json:"checksum"`
}
type resultRequest struct {
	Observations []agentObservation `json:"observations"`
	Evidence     []agentEvidence    `json:"evidence"`
}

func (h Agent) Result(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[resultRequest](w, r, 2<<20)
	if !ok {
		return
	}
	if len(input.Observations) > 500 || len(input.Evidence) > 500 {
		middleware.WriteError(w, r, http.StatusBadRequest, "RESULT_TOO_LARGE", "result item count exceeds policy")
		return
	}
	org, agent, id := middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), domain.ID(chi.URLParam(r, "id"))
	tx, err := h.Enrollment.Pool.Begin(r.Context())
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "result transaction could not start")
		return
	}
	defer tx.Rollback(r.Context())
	var moduleID string
	err = tx.QueryRow(r.Context(), `SELECT module_id FROM analysis_jobs WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='RUNNING' FOR UPDATE`, org, agent, id).Scan(&moduleID)
	if err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job is not running for this agent")
		return
	}
	for _, item := range input.Observations {
		if item.ObservedAt.IsZero() {
			item.ObservedAt = time.Now().UTC()
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO observations(organization_id,asset_id,module_id,job_id,category,status,severity,confidence,title,summary,meaning,impact,suggested_action,observed_at,evidence_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,0)`, org, item.AssetID, moduleID, id, item.Category, item.Status, item.Severity, item.Confidence, item.Title, item.Summary, item.Meaning, item.Impact, item.SuggestedAction, item.ObservedAt)
		if err != nil {
			middleware.WriteError(w, r, http.StatusBadRequest, "OBSERVATION_IMPORT_FAILED", "normalized observation is invalid")
			return
		}
	}
	for _, item := range input.Evidence {
		if len(item.Summary) > 4000 || len(item.ContentType)>200 || strings.ContainsAny(item.ContentType,"\r\n") {
			middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_SUMMARY_TOO_LARGE", "evidence summary exceeds policy")
			return
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO evidence(organization_id,job_id,source,content_type,summary,structured_data,checksum) VALUES($1,$2,$3,$4,$5,$6,$7)`, org, id, item.Source, item.ContentType, item.Summary, item.StructuredData, item.Checksum)
		if err != nil {
			middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_IMPORT_FAILED", "normalized evidence is invalid")
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE analysis_jobs SET status='SUCCEEDED',completed_at=now(),status_version=status_version+1 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='RUNNING'`, org, agent, id)
	if err != nil {
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'job.completed','job',$3,'success',jsonb_build_object('observations',$4,'evidence',$5))`, org, agent, id, len(input.Observations), len(input.Evidence))
	if err != nil {
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "result could not be committed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type failRequest struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

func (h Agent) Fail(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[failRequest](w, r, 8<<10)
	if !ok {
		return
	}
	if len(input.Summary) > 2000 || strings.TrimSpace(input.Code) == "" {
		middleware.WriteError(w, r, http.StatusBadRequest, "FAILURE_INVALID", "failure code or summary is invalid")
		return
	}
	id := domain.ID(chi.URLParam(r, "id"))
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `WITH changed AS (UPDATE analysis_jobs SET status='FAILED',completed_at=now(),status_version=status_version+1,rejection_code=$4 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status IN ('ASSIGNED','RUNNING') RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) SELECT $1,$2,'job.completed','job',id::text,'failed',jsonb_build_object('code',$4,'summary',$5) FROM changed`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), id, input.Code, input.Summary)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job failure transition was rejected")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
