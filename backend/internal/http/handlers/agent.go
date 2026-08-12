package handlers

import (
	"crypto/rand"
	"crypto/sha256"
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

type Agent struct {
	Enrollment        agents.EnrollmentService
	Signer            agents.JobEnvelopeSigner
	RequireSignedJobs bool
	Rotation          agents.RotationService
}

func (h Agent) RotateIdentity(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[struct {
		CSRPEM string `json:"csrPem"`
	}](w, r, 128<<10)
	if !ok {
		return
	}
	result, err := h.Rotation.Request(r.Context(), middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), input.CSRPEM)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "CERTIFICATE_ROTATION_INVALID", "certificate rotation request was rejected")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": result})
}

func (h Agent) ConfirmIdentityRotation(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[struct {
		CertificateID domain.ID `json:"certificateId"`
	}](w, r, 16<<10)
	if !ok {
		return
	}
	if err := h.Rotation.Confirm(r.Context(), middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), input.CertificateID, middleware.AgentFingerprint(r.Context())); err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "CERTIFICATE_ROTATION_CONFIRM_INVALID", "certificate rotation confirmation was rejected")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h Agent) RollbackIdentityRotation(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[struct {
		CertificateID domain.ID `json:"certificateId"`
	}](w, r, 16<<10)
	if !ok {
		return
	}
	if err := h.Rotation.Rollback(r.Context(), middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), input.CertificateID); err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "CERTIFICATE_ROTATION_ROLLBACK_INVALID", "certificate rotation rollback was rejected")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h Agent) Enroll(w http.ResponseWriter, r *http.Request) {
	var input agents.EnrollmentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "ENROLLMENT_REQUEST_INVALID", "enrollment request is invalid")
		return
	}
	if agents.RequireCompatible(input.ProtocolVersion) != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "PROTOCOL_INCOMPATIBLE", "agent protocol is incompatible with this control plane")
		return
	}
	result, err := h.Enrollment.Enroll(r.Context(), input)
	if err != nil {
		middleware.WriteError(w, r, http.StatusUnauthorized, "ENROLLMENT_FAILED", "enrollment could not be completed with the supplied token and identity")
		return
	}
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": result})
}
func (h Agent) Heartbeat(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[heartbeatRequest](w, r, 128<<10)
	if !ok {
		return
	}
	org, agentID := middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context())
	if input.AgentID != agentID || agents.RequireCompatible(input.ProtocolVersion) != nil || input.Timestamp.IsZero() {
		middleware.WriteError(w, r, http.StatusBadRequest, "PROTOCOL_INCOMPATIBLE", "heartbeat protocol or agent identity is incompatible")
		return
	}
	if input.ContractVersion != "" && agents.RequireCompatible(input.ContractVersion) != nil || input.CapabilitySchemaVersion != "" && agents.RequireCompatible(input.CapabilitySchemaVersion) != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "PROTOCOL_INCOMPATIBLE", "contract or capability schema major version is incompatible")
		return
	}
	if (input.Status != "ONLINE" && input.Status != "DEGRADED") || input.RunningJobs < 0 || input.AvailableSlots < 0 || len(input.CapabilitiesHash) != 64 {
		middleware.WriteError(w, r, http.StatusBadRequest, "HEARTBEAT_INVALID", "heartbeat state, slots or capabilities hash is invalid")
		return
	}
	if delta := time.Since(input.Timestamp); delta > 10*time.Minute || delta < -10*time.Minute {
		middleware.WriteError(w, r, http.StatusBadRequest, "HEARTBEAT_TIMESTAMP_INVALID", "heartbeat timestamp is outside the accepted clock window")
		return
	}
	health, err := json.Marshal(input.HealthSummary)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "HEARTBEAT_INVALID", "heartbeat health summary is invalid")
		return
	}
	compatibility := agents.Compatibility(input.ProtocolVersion)
	contractVersion := input.ContractVersion
	if contractVersion == "" {
		contractVersion = "1.0"
	}
	capabilitySchema := input.CapabilitySchemaVersion
	if capabilitySchema == "" {
		capabilitySchema = "1.0"
	}
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `UPDATE agents SET last_seen_at=now(),status='ONLINE',version=$3,hostname=$4,os=$5,arch=$6,protocol_version=$7,compatibility_status=$8,running_jobs=$9,available_slots=$10,capabilities_hash=NULLIF($11,''),health_summary=$12,contract_version=$13,capability_schema_version=$14 WHERE organization_id=$1 AND id=$2 AND status<>'REVOKED'`, org, agentID, input.AgentVersion, input.Hostname, input.OS, input.Architecture, input.ProtocolVersion, compatibility, input.RunningJobs, input.AvailableSlots, input.CapabilitiesHash, health, contractVersion, capabilitySchema)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusUnauthorized, "HEARTBEAT_REJECTED", "agent is no longer active")
		return
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "accepted", "protocolVersion": domain.AgentProtocolVersion, "compatibilityStatus": compatibility, "serverTime": time.Now().UTC()}})
}
func (h Agent) NextJob(w http.ResponseWriter, r *http.Request) {
	var compatibility string
	if err := h.Enrollment.Pool.QueryRow(r.Context(), `SELECT compatibility_status FROM agents WHERE organization_id=$1 AND id=$2 AND status<>'REVOKED'`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context())).Scan(&compatibility); err != nil || (compatibility != string(domain.AgentCompatible) && compatibility != string(domain.AgentUpgradeRecommended)) {
		middleware.WriteError(w, r, http.StatusConflict, "PROTOCOL_INCOMPATIBLE", "agent protocol is not compatible with job delivery")
		return
	}
	tx, err := h.Enrollment.Pool.Begin(r.Context())
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_POLL_FAILED", "job polling failed")
		return
	}
	defer tx.Rollback(r.Context())
	var envelope domain.JobEnvelope
	var timeout time.Time
	err = tx.QueryRow(r.Context(), `SELECT j.id::text,j.module_id,m.version,j.scope_id::text,s.environment,j.asset_id::text,j.service_id::text,j.diagnostic_run_id::text,j.vantage_point_id::text,s.type,j.normalized_target,j.parameters,j.risk_class,j.timeout_at,coalesce(j.authorization_reference,'scope:'||j.scope_id::text||':job:'||j.id::text) FROM analysis_jobs j JOIN authorized_scopes s ON s.id=j.scope_id AND s.organization_id=j.organization_id JOIN module_definitions m ON m.id=j.module_id WHERE j.organization_id=$1 AND j.agent_id=$2 AND j.status='QUEUED' AND j.timeout_at>now() ORDER BY j.queued_at,j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context())).Scan(&envelope.JobID, &envelope.ModuleID, &envelope.ModuleVersionRequirement, &envelope.ScopeID, &envelope.ScopeEnvironment, &envelope.AssetID, &envelope.ServiceID, &envelope.DiagnosticRunID, &envelope.VantagePointID, &envelope.Target.Type, &envelope.Target.Value, &envelope.ValidatedParameters, &envelope.RiskClass, &timeout, &envelope.AuthorizationReference)
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
	envelope.ProtocolVersion = domain.AgentProtocolVersion
	envelope.IssuedAt = now
	envelope.ExpiresAt = expires
	envelope.TimeoutSeconds = int(time.Until(timeout).Seconds())
	if envelope.TimeoutSeconds < 1 {
		envelope.TimeoutSeconds = 1
	}
	envelope.Nonce = hex.EncodeToString(nonce)
	if h.Signer != nil {
		envelope.SigningKeyID = h.Signer.KeyID()
		envelope.SignatureAlgorithm = h.Signer.Algorithm()
		envelope.Signature, err = h.Signer.Sign(r.Context(), envelope)
		if err != nil {
			middleware.WriteError(w, r, http.StatusInternalServerError, "JOB_SIGNING_FAILED", "job could not be signed")
			return
		}
	} else if h.RequireSignedJobs {
		middleware.WriteError(w, r, http.StatusServiceUnavailable, "JOB_SIGNING_UNAVAILABLE", "signed job policy is active but no signing key is available")
		return
	}
	tag, err := tx.Exec(r.Context(), `WITH changed AS (UPDATE analysis_jobs SET status='ASSIGNED',status_version=status_version+1,signing_key_id=NULLIF($4,''),signature_algorithm=NULLIF($5,''),signature=NULLIF($6,''),signature_issued_at=CASE WHEN $6<>'' THEN now() END WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='QUEUED' RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) SELECT $1,$2,CASE WHEN $6<>'' THEN 'job.signed' ELSE 'job.assigned_unsigned' END,'job',id::text,'success',jsonb_build_object('signingKeyId',NULLIF($4,''),'signatureAlgorithm',NULLIF($5,'')) FROM changed`, envelope.OrganizationID, envelope.AgentID, envelope.JobID, envelope.SigningKeyID, envelope.SignatureAlgorithm, envelope.Signature)
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
	EvidenceID      *domain.ID              `json:"evidenceId"`
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
	EvidenceID     domain.ID       `json:"evidenceId"`
	ArtifactID     *domain.ID      `json:"artifactId"`
	Source         string          `json:"source"`
	ContentType    string          `json:"contentType"`
	Summary        string          `json:"summary"`
	StructuredData json.RawMessage `json:"structuredData"`
	SHA256         string          `json:"sha256"`
	SizeBytes      int64           `json:"sizeBytes"`
	ArtifactKind   string          `json:"artifactKind"`
}
type resultMetric struct {
	Name         string                  `json:"name"`
	NumericValue *float64                `json:"numericValue"`
	TextValue    string                  `json:"textValue,omitempty"`
	Status       domain.NormalizedStatus `json:"status"`
	ObservedAt   time.Time               `json:"observedAt"`
}
type resultRequest struct {
	ProtocolVersion  string             `json:"protocolVersion"`
	ResultIdentity   string             `json:"resultIdentity"`
	ResultVersion    int                `json:"resultVersion"`
	JobID            domain.ID          `json:"jobId"`
	AgentID          domain.ID          `json:"agentId"`
	ModuleID         string             `json:"moduleId"`
	Status           string             `json:"status"`
	StartedAt        time.Time          `json:"startedAt"`
	CompletedAt      time.Time          `json:"completedAt"`
	Summary          string             `json:"summary"`
	Observations     []agentObservation `json:"observations"`
	Metrics          []resultMetric     `json:"metrics"`
	Warnings         []string           `json:"warnings"`
	EvidenceManifest []agentEvidence    `json:"evidenceManifest"`
	ToolVersion      string             `json:"toolVersion,omitempty"`
	Truncated        bool               `json:"truncated"`
}

func (h Agent) Result(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[resultRequest](w, r, 2<<20)
	if !ok {
		return
	}
	if len(input.Observations) > 500 || len(input.EvidenceManifest) > 500 || len(input.Metrics) > 1000 || len(input.Warnings) > 100 {
		middleware.WriteError(w, r, http.StatusBadRequest, "RESULT_TOO_LARGE", "result item count exceeds policy")
		return
	}
	org, agent, id := middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), domain.ID(chi.URLParam(r, "id"))
	if agents.RequireCompatible(input.ProtocolVersion) != nil || input.JobID != id || input.AgentID != agent || input.ResultIdentity == "" || input.ResultVersion < 1 || input.Status != "SUCCEEDED" {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_JOB", "result protocol, identity or status is invalid")
		return
	}
	if input.StartedAt.IsZero() || input.CompletedAt.IsZero() || input.CompletedAt.Before(input.StartedAt) || len(input.Summary) > 4000 {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_JOB", "result timestamps or summary are invalid")
		return
	}
	payload, _ := json.Marshal(input)
	payloadDigest := sha256.Sum256(payload)
	payloadChecksum := hex.EncodeToString(payloadDigest[:])
	tx, err := h.Enrollment.Pool.Begin(r.Context())
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "result transaction could not start")
		return
	}
	defer tx.Rollback(r.Context())
	var moduleID, jobStatus string
	var jobAssetID domain.ID
	err = tx.QueryRow(r.Context(), `SELECT module_id,status,asset_id::text FROM analysis_jobs WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status IN ('RUNNING','SUCCEEDED') FOR UPDATE`, org, agent, id).Scan(&moduleID, &jobStatus, &jobAssetID)
	if err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job is not running for this agent")
		return
	}
	if input.ModuleID != moduleID {
		middleware.WriteError(w, r, http.StatusBadRequest, "INVALID_JOB", "result module does not match the assigned job")
		return
	}
	var existingIdentity string
	var existingVersion int
	var existingChecksum string
	receiptErr := tx.QueryRow(r.Context(), `SELECT result_identity,result_version,payload_checksum FROM agent_result_receipts WHERE organization_id=$1 AND agent_id=$2 AND job_id=$3`, org, agent, id).Scan(&existingIdentity, &existingVersion, &existingChecksum)
	if receiptErr == nil {
		if existingIdentity == input.ResultIdentity && existingVersion == input.ResultVersion && existingChecksum == payloadChecksum {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		middleware.WriteError(w, r, http.StatusConflict, "RESULT_IDENTITY_CONFLICT", "a different result was already accepted for this job")
		return
	}
	if !errors.Is(receiptErr, pgx.ErrNoRows) || jobStatus != "RUNNING" {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job cannot accept a new result")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO agent_result_receipts(job_id,organization_id,agent_id,result_identity,result_version,payload_checksum) VALUES($1,$2,$3,$4,$5,$6)`, id, org, agent, input.ResultIdentity, input.ResultVersion, payloadChecksum)
	if err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "RESULT_IDENTITY_CONFLICT", "result receipt could not be reserved")
		return
	}
	for _, item := range input.EvidenceManifest {
		if item.EvidenceID == "" || len(item.SHA256) != 64 || item.SizeBytes < 0 || !validJSONObject(item.StructuredData) || len(item.Summary) > 4000 || len(item.ContentType) > 200 || strings.ContainsAny(item.ContentType, "\r\n") {
			middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_SUMMARY_TOO_LARGE", "evidence summary exceeds policy")
			return
		}
		tag, insertErr := tx.Exec(r.Context(), `INSERT INTO evidence(id,organization_id,job_id,source,content_type,summary,structured_data,checksum,module_id,agent_id,vantage_point_id,artifact_kind,size_bytes,observed_at,artifact_id,storage_key) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,j.vantage_point_id,NULLIF($11,''),$12,$13,a.id,a.storage_key FROM analysis_jobs j LEFT JOIN artifacts a ON a.organization_id=j.organization_id AND a.job_id=j.id AND a.id=$14 AND a.status='AVAILABLE' AND a.sha256=lower($8) AND a.size_bytes=$12 WHERE j.organization_id=$2 AND j.agent_id=$10 AND j.id=$3 AND ($14::uuid IS NULL OR a.id IS NOT NULL)`, item.EvidenceID, org, id, item.Source, item.ContentType, item.Summary, item.StructuredData, item.SHA256, moduleID, agent, item.ArtifactKind, item.SizeBytes, input.CompletedAt, item.ArtifactID)
		if insertErr != nil || tag.RowsAffected() != 1 {
			middleware.WriteError(w, r, http.StatusBadRequest, "EVIDENCE_ARTIFACT_INVALID", "evidence artifact is unavailable, unverified or outside the authorized context")
			return
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'evidence.created','evidence',$3,'success',jsonb_build_object('artifactId',$4::text))`, org, agent, item.EvidenceID, item.ArtifactID)
		if err != nil {
			middleware.WriteError(w, r, http.StatusInternalServerError, "EVIDENCE_IMPORT_FAILED", "evidence audit event could not be stored")
			return
		}
	}
	for _, item := range input.Observations {
		if item.AssetID != nil && *item.AssetID != jobAssetID {
			middleware.WriteError(w, r, http.StatusBadRequest, "OBSERVATION_ASSET_INVALID", "observation asset does not match the authorized job")
			return
		}
		item.AssetID = &jobAssetID
		if item.ObservedAt.IsZero() {
			item.ObservedAt = time.Now().UTC()
		}
		var observationID domain.ID
		err = tx.QueryRow(r.Context(), `INSERT INTO observations(organization_id,asset_id,module_id,job_id,category,status,severity,confidence,title,summary,meaning,impact,suggested_action,observed_at,evidence_count,evidence_id) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN e.id IS NULL THEN 0 ELSE 1 END,e.id FROM (SELECT 1) seed LEFT JOIN evidence e ON e.organization_id=$1 AND e.job_id=$4 AND e.id=$15 WHERE $15::uuid IS NULL OR e.id IS NOT NULL RETURNING id::text`, org, item.AssetID, moduleID, id, item.Category, item.Status, item.Severity, item.Confidence, item.Title, item.Summary, item.Meaning, item.Impact, item.SuggestedAction, item.ObservedAt, item.EvidenceID).Scan(&observationID)
		if err != nil {
			middleware.WriteError(w, r, http.StatusBadRequest, "OBSERVATION_EVIDENCE_INVALID", "observation evidence is missing or outside the authorized context")
			return
		}
		_, err = tx.Exec(r.Context(), `UPDATE evidence SET observation_id=$4 WHERE organization_id=$1 AND job_id=$2 AND id=$3 AND observation_id IS NULL; INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$5,'observation.created','observation',$4::text,'success',jsonb_build_object('evidenceId',$3::text))`, org, id, item.EvidenceID, observationID, agent)
		if err != nil {
			middleware.WriteError(w, r, http.StatusInternalServerError, "OBSERVATION_IMPORT_FAILED", "observation relationship could not be stored")
			return
		}
	}
	allowedMetrics := map[string]bool{"AVAILABILITY": true, "LATENCY_MS": true, "PACKET_LOSS_PERCENT": true, "DNS_DURATION_MS": true, "TCP_CONNECT_DURATION_MS": true, "TLS_DAYS_UNTIL_EXPIRATION": true, "HTTP_DURATION_MS": true, "HTTP_STATUS": true}
	for _, metric := range input.Metrics {
		if !allowedMetrics[metric.Name] {
			middleware.WriteError(w, r, http.StatusBadRequest, "RESULT_METRIC_INVALID", "result contains an unsupported metric")
			return
		}
		if metric.ObservedAt.IsZero() {
			metric.ObservedAt = input.CompletedAt
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO monitor_samples(organization_id,asset_id,service_id,vantage_point_id,job_id,metric,numeric_value,text_value,status,observed_at) SELECT organization_id,asset_id,service_id,vantage_point_id,id,$4,$5,NULLIF($6,''),$7,$8 FROM analysis_jobs WHERE organization_id=$1 AND agent_id=$2 AND id=$3`, org, agent, id, metric.Name, metric.NumericValue, metric.TextValue, metric.Status, metric.ObservedAt)
		if err != nil {
			middleware.WriteError(w, r, http.StatusBadRequest, "RESULT_METRIC_INVALID", "result metric could not be stored")
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE analysis_jobs SET status='SUCCEEDED',started_at=coalesce(started_at,$4),completed_at=$5,status_version=status_version+1,result_identity=$6,result_version=$7 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='RUNNING'`, org, agent, id, input.StartedAt, input.CompletedAt, input.ResultIdentity, input.ResultVersion)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "job result state could not be stored")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'job.completed','job',$3,'success',jsonb_build_object('observations',$4,'evidence',$5,'resultIdentity',$6,'truncated',$7))`, org, agent, id, len(input.Observations), len(input.EvidenceManifest), input.ResultIdentity, input.Truncated)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "job result audit event could not be stored")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "RESULT_IMPORT_FAILED", "result could not be committed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type failRequest struct {
	ProtocolVersion string    `json:"protocolVersion"`
	JobID           domain.ID `json:"jobId"`
	AgentID         domain.ID `json:"agentId"`
	Code            string    `json:"code"`
	Summary         string    `json:"summary"`
	OccurredAt      time.Time `json:"occurredAt"`
	Retryable       bool      `json:"retryable"`
}

func (h Agent) Fail(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[failRequest](w, r, 8<<10)
	if !ok {
		return
	}
	allowed := map[string]bool{"MODULE_UNAVAILABLE": true, "TOOL_NOT_FOUND": true, "CAPABILITY_MISSING": true, "INVALID_JOB": true, "JOB_EXPIRED": true, "TARGET_REJECTED": true, "TIMEOUT": true, "PROCESS_FAILED": true, "OUTPUT_LIMIT_EXCEEDED": true, "ARTIFACT_ERROR": true, "CANCELLED": true, "PROTOCOL_INCOMPATIBLE": true, "SIGNATURE_INVALID": true, "REPLAY_REJECTED": true, "INTERNAL_ERROR": true}
	id := domain.ID(chi.URLParam(r, "id"))
	if len(input.Summary) > 2000 || input.OccurredAt.IsZero() || !allowed[input.Code] || input.JobID != id || input.AgentID != middleware.AgentID(r.Context()) || agents.RequireCompatible(input.ProtocolVersion) != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "FAILURE_INVALID", "failure code or summary is invalid")
		return
	}
	tag, err := h.Enrollment.Pool.Exec(r.Context(), `WITH changed AS (UPDATE analysis_jobs SET status=CASE $4 WHEN 'CANCELLED' THEN 'CANCELLED' WHEN 'TIMEOUT' THEN 'TIMED_OUT' ELSE 'FAILED' END,completed_at=now(),status_version=status_version+1,rejection_code=$4 WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status IN ('ASSIGNED','RUNNING') RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) SELECT $1,$2,CASE WHEN $4='SIGNATURE_INVALID' THEN 'job.signature_invalid' WHEN $4='REPLAY_REJECTED' THEN 'job.replay_rejected' WHEN $4='PROTOCOL_INCOMPATIBLE' THEN 'agent.protocol_incompatible' ELSE 'job.completed' END,'job',id::text,'failed',jsonb_build_object('code',$4,'summary',$5) FROM changed`, middleware.OrganizationID(r.Context()), middleware.AgentID(r.Context()), id, input.Code, input.Summary)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusConflict, "JOB_STATE_INVALID", "job failure transition was rejected")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validJSONObject(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	return len(data) > 0 && json.Unmarshal(data, &object) == nil && object != nil
}
