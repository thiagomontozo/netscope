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
func (s ControlPlane) ValidateAgentFingerprint(ctx context.Context, fingerprint string) (domain.ID, domain.ID, error) {
	var org, agent domain.ID
	err := s.Pool.QueryRow(ctx, `SELECT organization_id::text,id::text FROM agents WHERE identity_fingerprint=$1 AND status IN ('ONLINE','DEGRADED','OFFLINE') AND (certificate_expires_at IS NULL OR certificate_expires_at>now())`, fingerprint).Scan(&org, &agent)
	return org, agent, err
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
func (s ControlPlane) WithinMaintenanceWindow(ctx context.Context, organizationID domain.ID, now time.Time) bool {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM maintenance_windows WHERE organization_id=$1 AND enabled) OR EXISTS(SELECT 1 FROM maintenance_windows WHERE organization_id=$1 AND enabled AND $2>=starts_at AND $2<ends_at)`, organizationID, now).Scan(&allowed)
	return err == nil && allowed
}
func (s ControlPlane) ModuleEnabled(ctx context.Context, organizationID domain.ID, moduleID string) (bool, error) {
	var enabled bool
	err := s.Pool.QueryRow(ctx, `SELECT coalesce((SELECT enabled FROM organization_module_settings WHERE organization_id=$1 AND module_id=$2),(SELECT enabled FROM module_definitions WHERE id=$2),false)`, organizationID, moduleID).Scan(&enabled)
	return enabled, err
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
	_, err := s.Pool.Exec(ctx, `INSERT INTO analysis_jobs(id,organization_id,module_id,asset_id,service_id,diagnostic_run_id,vantage_point_id,scope_id,agent_id,requested_by,parameters,normalized_target,risk_class,status,created_at,queued_at,timeout_at,protocol_version,authorization_reference) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15,$16,$17,'scope:'||$8::text||':job:'||$1::text)`, job.ID, job.OrganizationID, job.ModuleID, job.AssetID, job.ServiceID, job.DiagnosticRunID, job.VantagePointID, job.ScopeID, job.AgentID, job.RequestedBy, job.Parameters, normalizedTarget, job.RiskClass, job.Status, job.CreatedAt, job.TimeoutAt, domain.AgentProtocolVersion)
	return err
}
func (s ControlPlane) ValidateJobContext(ctx context.Context, organizationID, assetID domain.ID, serviceID, diagnosticRunID, vantagePointID *domain.ID, agentID domain.ID) error {
	var valid bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assets a JOIN agents ag ON ag.organization_id=a.organization_id WHERE a.organization_id=$1 AND a.id=$2 AND ag.id=$3 AND ($4::uuid IS NULL OR EXISTS(SELECT 1 FROM network_services ns WHERE ns.organization_id=$1 AND ns.id=$4 AND ns.asset_id=a.id)) AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM diagnostic_runs dr WHERE dr.organization_id=$1 AND dr.id=$5 AND dr.asset_id=a.id AND (dr.service_id IS NULL OR dr.service_id=$4))) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM vantage_points vp WHERE vp.organization_id=$1 AND vp.id=$6 AND vp.active AND (vp.agent_id IS NULL OR vp.agent_id=$3))))`, organizationID, assetID, agentID, serviceID, diagnosticRunID, vantagePointID).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("job context does not belong to organization")
	}
	return nil
}
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
