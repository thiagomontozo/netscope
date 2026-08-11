package database

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type ControlPlane struct{ Pool *pgxpool.Pool }

func (s ControlPlane) ValidateSession(ctx context.Context, tokenHash string) (domain.ID, domain.ID, error) {
	var org, user domain.ID
	err := s.Pool.QueryRow(ctx, `SELECT s.organization_id,s.user_id FROM sessions s JOIN users u ON u.id=s.user_id AND u.organization_id=s.organization_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active`, tokenHash).Scan(&org, &user)
	if err == nil {
		_, _ = s.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE token_hash=$1`, tokenHash)
	}
	return org, user, err
}
func (s ControlPlane) GetForOrganization(ctx context.Context, organizationID, scopeID domain.ID) (domain.AuthorizedScope, error) {
	var v domain.AuthorizedScope
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,type,value,environment,status,coalesce(verification_type,''),verified_at,verified_by,valid_from,valid_until,notes,created_at FROM authorized_scopes WHERE organization_id=$1 AND id=$2`, organizationID, scopeID).Scan(&v.ID, &v.OrganizationID, &v.Type, &v.Value, &v.Environment, &v.Status, &v.VerificationType, &v.VerifiedAt, &v.VerifiedBy, &v.ValidFrom, &v.ValidUntil, &v.Notes, &v.CreatedAt)
	return v, err
}
func (s ControlPlane) Has(ctx context.Context, organizationID, userID domain.ID, permission string) (bool, error) {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.organization_id=$1 AND u.id=$2 AND u.active AND (r.organization_id=$1 OR r.organization_id IS NULL) AND p.name=$3)`, organizationID, userID, permission).Scan(&allowed)
	return allowed, err
}
func (s ControlPlane) Supports(ctx context.Context, organizationID, agentID domain.ID, required []string) (bool, error) {
	var capabilities []byte
	var status string
	err := s.Pool.QueryRow(ctx, `SELECT capabilities,status FROM agents WHERE organization_id=$1 AND id=$2`, organizationID, agentID).Scan(&capabilities, &status)
	if err != nil {
		return false, err
	}
	if status != "ONLINE" && status != "DEGRADED" {
		return false, nil
	}
	var available []string
	if err := json.Unmarshal(capabilities, &available); err != nil {
		return false, err
	}
	set := map[string]bool{}
	for _, item := range available {
		set[item] = true
	}
	for _, item := range required {
		if !set[item] {
			return false, nil
		}
	}
	return true, nil
}
func (s ControlPlane) WithinMaintenanceWindow(context.Context, domain.ID, time.Time) bool {
	return true
}
func (s ControlPlane) AllowRate(ctx context.Context, organizationID, scopeID domain.ID, moduleID string) bool {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT count(*) < 10 FROM analysis_jobs WHERE organization_id=$1 AND scope_id=$2 AND module_id=$3 AND created_at > now()-interval '1 minute'`, organizationID, scopeID, moduleID).Scan(&allowed)
	return err == nil && allowed
}
func (s ControlPlane) ConcurrentJobs(ctx context.Context, organizationID domain.ID) (int, error) {
	var count int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM analysis_jobs WHERE organization_id=$1 AND status IN ('QUEUED','ASSIGNED','RUNNING')`, organizationID).Scan(&count)
	return count, err
}
func (s ControlPlane) CreateAuthorized(ctx context.Context, job domain.AnalysisJob, normalizedTarget string) error {
	if job.OrganizationID == "" || job.ScopeID == "" || job.AgentID == "" {
		return errors.New("job identity context is incomplete")
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO analysis_jobs(id,organization_id,module_id,asset_id,scope_id,agent_id,requested_by,parameters,normalized_target,risk_class,status,created_at,queued_at,timeout_at) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13)`, job.ID, job.OrganizationID, job.ModuleID, job.AssetID, job.ScopeID, job.AgentID, job.RequestedBy, job.Parameters, normalizedTarget, job.RiskClass, job.Status, job.CreatedAt, job.TimeoutAt)
	return err
}
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
