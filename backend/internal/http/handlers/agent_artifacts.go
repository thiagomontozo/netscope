package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/artifacts"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
)

type AgentArtifacts struct {
	Pool                             *pgxpool.Pool
	Storage                          storage.ObjectStorage
	Tokens                           artifacts.TokenManager
	MaxDownloadBytes, MaxUploadBytes int64
	TempDir                          string
}

func (h AgentArtifacts) Create(w http.ResponseWriter, r *http.Request) {
	manifest, ok := decode[artifacts.Manifest](w, r, 32<<10)
	if !ok {
		return
	}
	org, agent := string(middleware.OrganizationID(r.Context())), string(middleware.AgentID(r.Context()))
	allowedType := map[string]bool{"PCAP": true, "RAW_EVIDENCE": true, "JOB_INPUT": true, "JOB_OUTPUT": true, "REPORT": true}
	allowedContent := map[string]bool{"application/octet-stream": true, "application/json": true, "text/plain": true, "application/vnd.tcpdump.pcap": true}
	checksumBytes, checksumErr := hex.DecodeString(manifest.SHA256)
	if manifest.ProtocolVersion != "1.0" || manifest.OrganizationID != org || manifest.JobID == nil || manifest.Direction != artifacts.DirectionFromAgent || !allowedType[manifest.Type] || !allowedContent[manifest.ContentType] || manifest.SizeBytes < 0 || manifest.SizeBytes > h.MaxUploadBytes || checksumErr != nil || len(checksumBytes) != 32 {
		middleware.WriteError(w, r, http.StatusBadRequest, "ARTIFACT_MANIFEST_INVALID", "artifact manifest violates transfer policy")
		return
	}
	storageKey := "artifacts/" + org + "/" + manifest.ArtifactID
	tag, err := h.Pool.Exec(r.Context(), `WITH created AS (INSERT INTO artifacts(id,organization_id,job_id,type,direction,content_type,original_name,storage_key,size_bytes,sha256,status,created_at,expires_at,uploaded_by_agent_id) SELECT $1,$2,j.id,$5,$6,$7,NULLIF($8,''),$9,$10,lower($11),'PENDING',now(),$12,$3 FROM analysis_jobs j WHERE j.organization_id=$2 AND j.agent_id=$3 AND j.id=$4 AND j.status IN ('ASSIGNED','RUNNING') RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome) SELECT $2,$3,'artifact.created','artifact',id::text,'success' FROM created`, manifest.ArtifactID, org, agent, *manifest.JobID, manifest.Type, manifest.Direction, manifest.ContentType, manifest.OriginalName, storageKey, manifest.SizeBytes, manifest.SHA256, manifest.ExpiresAt)
	if err != nil || tag.RowsAffected() != 1 {
		middleware.WriteError(w, r, http.StatusConflict, "ARTIFACT_MANIFEST_REJECTED", "artifact manifest could not be associated with the active job")
		return
	}
	manifest.Status = "PENDING"
	manifest.CreatedAt = time.Now().UTC()
	manifest.UploadedByAgentID = &agent
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": manifest})
}

func (h AgentArtifacts) Authorize(w http.ResponseWriter, r *http.Request) {
	input, ok := decode[struct {
		JobID   string `json:"jobId"`
		Purpose string `json:"purpose"`
	}](w, r, 16<<10)
	if !ok {
		return
	}
	artifactID := chi.URLParam(r, "id")
	org := string(middleware.OrganizationID(r.Context()))
	agent := string(middleware.AgentID(r.Context()))
	var direction, status string
	var size int64
	err := h.Pool.QueryRow(r.Context(), `SELECT a.direction,a.status,a.size_bytes FROM artifacts a JOIN analysis_jobs j ON j.id=a.job_id AND j.organization_id=a.organization_id WHERE a.organization_id=$1 AND a.id=$2 AND a.job_id=$3 AND j.agent_id=$4`, org, artifactID, input.JobID, agent).Scan(&direction, &status, &size)
	if err != nil || status == "EXPIRED" || (input.Purpose == artifacts.PurposeDownload && (direction != artifacts.DirectionToAgent || status != "AVAILABLE")) || (input.Purpose == artifacts.PurposeUpload && (direction != artifacts.DirectionFromAgent || status != "PENDING")) {
		middleware.WriteError(w, r, http.StatusForbidden, "ARTIFACT_AUTHORIZATION_REJECTED", "artifact transfer is not authorized")
		return
	}
	if (input.Purpose == artifacts.PurposeDownload && size > h.MaxDownloadBytes) || (input.Purpose == artifacts.PurposeUpload && size > h.MaxUploadBytes) {
		middleware.WriteError(w, r, http.StatusRequestEntityTooLarge, "ARTIFACT_SIZE_LIMIT_EXCEEDED", "artifact exceeds transfer policy")
		return
	}
	token, err := h.Tokens.Issue(artifacts.TransferClaims{ArtifactID: artifactID, OrganizationID: org, AgentID: agent, JobID: input.JobID, Purpose: input.Purpose})
	if err != nil {
		middleware.WriteError(w, r, http.StatusServiceUnavailable, "ARTIFACT_AUTHORIZATION_UNAVAILABLE", "artifact authorization is unavailable")
		return
	}
	_, _ = h.Pool.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'artifact.download_authorized','artifact',$3,'success',jsonb_build_object('purpose',$4))`, org, agent, artifactID, input.Purpose)
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"token": token, "purpose": input.Purpose, "expiresInSeconds": int(h.Tokens.TTL.Seconds())}})
}

func (h AgentArtifacts) Download(w http.ResponseWriter, r *http.Request) {
	artifactID := chi.URLParam(r, "id")
	org := string(middleware.OrganizationID(r.Context()))
	agent := string(middleware.AgentID(r.Context()))
	job := r.URL.Query().Get("jobId")
	if _, err := h.Tokens.Verify(artifactToken(r), artifacts.TransferClaims{ArtifactID: artifactID, OrganizationID: org, AgentID: agent, JobID: job, Purpose: artifacts.PurposeDownload}); err != nil {
		middleware.WriteError(w, r, http.StatusForbidden, "ARTIFACT_TOKEN_INVALID", "artifact transfer token is invalid or expired")
		return
	}
	var key, contentType, checksum string
	var size int64
	if err := h.Pool.QueryRow(r.Context(), `SELECT storage_key,content_type,size_bytes,sha256 FROM artifacts WHERE organization_id=$1 AND id=$2 AND job_id=$3 AND direction='CONTROL_PLANE_TO_AGENT' AND status='AVAILABLE'`, org, artifactID, job).Scan(&key, &contentType, &size, &checksum); err != nil || size > h.MaxDownloadBytes {
		middleware.WriteError(w, r, http.StatusNotFound, "ARTIFACT_NOT_AVAILABLE", "artifact is not available")
		return
	}
	source, err := h.Storage.Open(r.Context(), key)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "ARTIFACT_NOT_AVAILABLE", "artifact bytes are not available")
		return
	}
	defer source.Close()
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", stringInt(size))
	w.Header().Set("X-NetScope-Artifact-SHA256", checksum)
	_, _ = io.CopyN(w, source, size)
}

func (h AgentArtifacts) Upload(w http.ResponseWriter, r *http.Request) {
	artifactID := chi.URLParam(r, "id")
	org := string(middleware.OrganizationID(r.Context()))
	agent := string(middleware.AgentID(r.Context()))
	job := r.URL.Query().Get("jobId")
	if _, err := h.Tokens.Verify(artifactToken(r), artifacts.TransferClaims{ArtifactID: artifactID, OrganizationID: org, AgentID: agent, JobID: job, Purpose: artifacts.PurposeUpload}); err != nil {
		middleware.WriteError(w, r, http.StatusForbidden, "ARTIFACT_TOKEN_INVALID", "artifact transfer token is invalid or expired")
		return
	}
	var key, checksum string
	var size int64
	if err := h.Pool.QueryRow(r.Context(), `UPDATE artifacts SET status='UPLOADING' WHERE organization_id=$1 AND id=$2 AND job_id=$3 AND direction='AGENT_TO_CONTROL_PLANE' AND status='PENDING' RETURNING storage_key,size_bytes,sha256`, org, artifactID, job).Scan(&key, &size, &checksum); err != nil {
		middleware.WriteError(w, r, http.StatusConflict, "ARTIFACT_UPLOAD_STATE_INVALID", "artifact is not pending upload")
		return
	}
	temporary, err := os.CreateTemp(h.TempDir, "netscope-artifact-*.part")
	if err != nil {
		h.fail(r, org, agent, artifactID, "storage")
		middleware.WriteError(w, r, http.StatusInternalServerError, "ARTIFACT_UPLOAD_FAILED", "artifact upload failed")
		return
	}
	path := temporary.Name()
	defer os.Remove(path)
	defer temporary.Close()
	hash := sha256.New()
	limited := &io.LimitedReader{R: r.Body, N: h.MaxUploadBytes + 1}
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), limited)
	actual := hex.EncodeToString(hash.Sum(nil))
	if copyErr != nil || written != size || written > h.MaxUploadBytes || !strings.EqualFold(actual, checksum) {
		h.fail(r, org, agent, artifactID, "checksum")
		code := "ARTIFACT_UPLOAD_FAILED"
		if !strings.EqualFold(actual, checksum) {
			code = "ARTIFACT_CHECKSUM_MISMATCH"
		}
		middleware.WriteError(w, r, http.StatusUnprocessableEntity, code, "artifact size or checksum validation failed")
		return
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil || h.Storage.Put(r.Context(), key, temporary) != nil {
		h.fail(r, org, agent, artifactID, "storage")
		middleware.WriteError(w, r, http.StatusInternalServerError, "ARTIFACT_UPLOAD_FAILED", "artifact storage failed")
		return
	}
	_, err = h.Pool.Exec(r.Context(), `WITH changed AS (UPDATE artifacts SET status='AVAILABLE',verified_at=now(),uploaded_by_agent_id=$2 WHERE organization_id=$1 AND id=$3 AND status='UPLOADING' RETURNING id) INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome) SELECT $1,$2,'artifact.uploaded','artifact',id::text,'success' FROM changed`, org, agent, artifactID)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "ARTIFACT_UPLOAD_FAILED", "artifact metadata finalization failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h AgentArtifacts) fail(r *http.Request, org, agent, id, reason string) {
	_, _ = h.Pool.Exec(r.Context(), `UPDATE artifacts SET status='FAILED' WHERE organization_id=$1 AND id=$2; INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$3,'artifact.checksum_failed','artifact',$2,'failure',jsonb_build_object('reason',$4))`, org, id, agent, reason)
}
func stringInt(value int64) string { return strconv.FormatInt(value, 10) }
func artifactToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Artifact ")
}
