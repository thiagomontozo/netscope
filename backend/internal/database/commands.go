package database

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type Commands struct{ Pool *pgxpool.Pool }
type AssetInput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Hostname    string `json:"hostname"`
	IPAddress   string `json:"ipAddress"`
	Environment string `json:"environment"`
	Criticality string `json:"criticality"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
}
type ScopeInput struct {
	Type             string    `json:"type"`
	Value            string    `json:"value"`
	Environment      string    `json:"environment"`
	VerificationType string    `json:"verificationType"`
	ValidFrom        time.Time `json:"validFrom"`
	ValidUntil       time.Time `json:"validUntil"`
	Notes            string    `json:"notes"`
}
type ScheduleInput struct {
	ModuleID         string          `json:"moduleId"`
	ScopeID          domain.ID       `json:"scopeId"`
	AgentID          domain.ID       `json:"agentId"`
	AssetID          domain.ID       `json:"assetId"`
	ServiceID        *domain.ID      `json:"serviceId"`
	VantagePointID   *domain.ID      `json:"vantagePointId"`
	Parameters       json.RawMessage `json:"parameters"`
	FrequencySeconds int             `json:"frequencySeconds"`
	Enabled          bool            `json:"enabled"`
}
type UserInput struct {
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	RoleID       domain.ID `json:"roleId"`
}

func (c Commands) CreateAsset(ctx context.Context, org, user domain.ID, in AssetInput, requestID string) (domain.ID, error) {
	var id domain.ID
	err := c.Pool.QueryRow(ctx, `WITH created AS (INSERT INTO assets(organization_id,name,type,hostname,ip_address,environment,criticality,owner,description) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,'')::inet,$6,$7,NULLIF($8,''),NULLIF($9,'') RETURNING id) INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) SELECT $1,$10,'asset.created','asset',id::text,$11,'success' FROM created RETURNING resource_id`, org, in.Name, in.Type, in.Hostname, in.IPAddress, in.Environment, in.Criticality, in.Owner, in.Description, user, requestID).Scan(&id)
	return id, err
}
func (c Commands) UpdateAsset(ctx context.Context, org, user, id domain.ID, in AssetInput, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `UPDATE assets SET name=$3,type=$4,hostname=NULLIF($5,''),ip_address=NULLIF($6,'')::inet,environment=$7,criticality=$8,owner=NULLIF($9,''),description=NULLIF($10,''),updated_at=now() WHERE organization_id=$1 AND id=$2`, org, id, in.Name, in.Type, in.Hostname, in.IPAddress, in.Environment, in.Criticality, in.Owner, in.Description)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("asset not found")
	}
	return c.audit(ctx, org, user, "asset.updated", "asset", id, requestID, "success", nil)
}
func (c Commands) DeleteAsset(ctx context.Context, org, user, id domain.ID, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `DELETE FROM assets WHERE organization_id=$1 AND id=$2`, org, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("asset not found or referenced")
	}
	return c.audit(ctx, org, user, "asset.deleted", "asset", id, requestID, "success", nil)
}
func (c Commands) CreateScope(ctx context.Context, org, user domain.ID, in ScopeInput, normalized string, requestID string) (domain.ID, error) {
	var id domain.ID
	err := c.Pool.QueryRow(ctx, `WITH created AS (INSERT INTO authorized_scopes(organization_id,type,value,environment,status,verification_type,valid_from,valid_until,notes) VALUES($1,$2,$3,$4,'PENDING',NULLIF($5,''),$6,$7,$8) RETURNING id) INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome,metadata) SELECT $1,$9,'scope.created','scope',id::text,$10,'success',jsonb_build_object('normalizedTarget',$3) FROM created RETURNING resource_id`, org, in.Type, normalized, in.Environment, in.VerificationType, in.ValidFrom, in.ValidUntil, in.Notes, user, requestID).Scan(&id)
	return id, err
}
func (c Commands) SetScopeStatus(ctx context.Context, org, user, id domain.ID, status, event, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `UPDATE authorized_scopes SET status=$3,verified_at=CASE WHEN $3 IN ('VERIFIED','APPROVED') THEN now() ELSE verified_at END,verified_by=CASE WHEN $3 IN ('VERIFIED','APPROVED') THEN $4 ELSE verified_by END WHERE organization_id=$1 AND id=$2`, org, id, status, user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("scope not found")
	}
	return c.audit(ctx, org, user, event, "scope", id, requestID, "success", nil)
}
func (c Commands) SetFindingStatus(ctx context.Context, org, user, id domain.ID, status, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `UPDATE findings SET status=$3,resolved_at=CASE WHEN $3='RESOLVED' THEN now() ELSE NULL END,resolved_by=CASE WHEN $3='RESOLVED' THEN $4 ELSE NULL END WHERE organization_id=$1 AND id=$2`, org, id, status, user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("finding not found")
	}
	return c.audit(ctx, org, user, "finding."+status, "finding", id, requestID, "success", nil)
}
func (c Commands) CreateSchedule(ctx context.Context, org, user domain.ID, in ScheduleInput, requestID string) (domain.ID, error) {
	var id domain.ID
	err := c.Pool.QueryRow(ctx, `WITH created AS (INSERT INTO schedules(organization_id,module_id,scope_id,agent_id,asset_id,service_id,vantage_point_id,parameters,frequency_seconds,enabled,next_run_at,created_by) SELECT $1,$2,s.id,a.id,asset.id,service.id,vantage.id,$8,$9,$10,now()+make_interval(secs=>$9),$11 FROM authorized_scopes s JOIN agents a ON a.organization_id=s.organization_id JOIN assets asset ON asset.organization_id=s.organization_id AND asset.id=$5 LEFT JOIN network_services service ON service.organization_id=s.organization_id AND service.asset_id=asset.id AND service.id=$6 LEFT JOIN vantage_points vantage ON vantage.organization_id=s.organization_id AND vantage.active AND vantage.id=$7 WHERE s.organization_id=$1 AND s.id=$3 AND s.status IN ('VERIFIED','APPROVED') AND now()>=s.valid_from AND now()<s.valid_until AND a.id=$4 AND a.status IN ('ONLINE','DEGRADED') AND ($6::uuid IS NULL OR service.id IS NOT NULL) AND ($7::uuid IS NULL OR (vantage.id IS NOT NULL AND (vantage.agent_id IS NULL OR vantage.agent_id=a.id))) RETURNING id) INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) SELECT $1,$11,'schedule.created','schedule',id::text,$12,'success' FROM created RETURNING resource_id`, org, in.ModuleID, in.ScopeID, in.AgentID, in.AssetID, in.ServiceID, in.VantagePointID, in.Parameters, in.FrequencySeconds, in.Enabled, user, requestID).Scan(&id)
	return id, err
}
func (c Commands) SetScheduleEnabled(ctx context.Context, org, user, id domain.ID, enabled bool, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `UPDATE schedules SET enabled=$3 WHERE organization_id=$1 AND id=$2`, org, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("schedule not found")
	}
	return c.audit(ctx, org, user, "schedule.changed", "schedule", id, requestID, "success", map[string]any{"enabled": enabled})
}
func (c Commands) SetModuleEnabled(ctx context.Context, org, user domain.ID, moduleID string, enabled bool, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `INSERT INTO organization_module_settings(organization_id,module_id,enabled,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(organization_id,module_id) DO UPDATE SET enabled=excluded.enabled,updated_by=excluded.updated_by,updated_at=now()`, org, moduleID, enabled, user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("module not found")
	}
	return c.audit(ctx, org, user, map[bool]string{true: "module.enabled", false: "module.disabled"}[enabled], "module", domain.ID(moduleID), requestID, "success", nil)
}
func (c Commands) CancelJob(ctx context.Context, org, user, id domain.ID, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `WITH requested AS (INSERT INTO job_cancellation_requests(job_id,organization_id,requested_by,reason) SELECT id,$1,$3,'cancelled by authorized operator' FROM analysis_jobs WHERE organization_id=$1 AND id=$2 AND status IN ('ASSIGNED','RUNNING') ON CONFLICT(job_id) DO NOTHING) UPDATE analysis_jobs SET status='CANCELLED',completed_at=now(),status_version=status_version+1 WHERE organization_id=$1 AND id=$2 AND status IN ('PENDING','QUEUED','ASSIGNED','RUNNING')`, org, id, user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("job is terminal or missing")
	}
	return c.audit(ctx, org, user, "job.cancelled", "job", id, requestID, "success", nil)
}
func (c Commands) CreateUser(ctx context.Context, org, actor domain.ID, in UserInput, requestID string) (domain.ID, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var id domain.ID
	err = tx.QueryRow(ctx, `INSERT INTO users(organization_id,name,email,password_hash) VALUES($1,$2,lower($3),$4) RETURNING id::text`, org, in.Name, in.Email, in.PasswordHash).Scan(&id)
	if err != nil {
		return "", err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1,r.id FROM roles r WHERE r.id=$2 AND (r.organization_id=$3 OR r.organization_id IS NULL)`, id, in.RoleID, org)
	if err != nil || tag.RowsAffected() != 1 {
		return "", errors.New("role is not available to this organization")
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) VALUES($1,$2,'user.created','user',$3,$4,'success')`, org, actor, id, requestID)
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}
func (c Commands) CreateEnrollmentToken(ctx context.Context, org, user domain.ID, digest, requestedName string, expires time.Time, requestID string) error {
	_, err := c.Pool.Exec(ctx, `WITH created AS (INSERT INTO agent_enrollment_tokens(organization_id,token_hash,created_by,expires_at,requested_name) VALUES($1,$2,$3,$4,NULLIF($5,'')) RETURNING id) INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) SELECT $1,$3,'agent.enrollment_token_created','agent_enrollment_token',id::text,$6,'success' FROM created`, org, digest, user, expires, requestedName, requestID)
	return err
}
func (c Commands) RevokeAgent(ctx context.Context, org, user, id domain.ID, requestID string) error {
	tag, err := c.Pool.Exec(ctx, `UPDATE agents SET status='REVOKED' WHERE organization_id=$1 AND id=$2 AND status<>'REVOKED'`, org, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("agent not found")
	}
	return c.audit(ctx, org, user, "agent.revoked", "agent", id, requestID, "success", nil)
}
func (c Commands) CreateRole(ctx context.Context, org, user domain.ID, name, requestID string) (domain.ID, error) {
	var id domain.ID
	err := c.Pool.QueryRow(ctx, `WITH created AS (INSERT INTO roles(organization_id,name,system) VALUES($1,$2,false) RETURNING id) INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) SELECT $1,$3,'role.created','role',id::text,$4,'success' FROM created RETURNING resource_id`, org, name, user, requestID).Scan(&id)
	return id, err
}
func (c Commands) SetRolePermissions(ctx context.Context, org, user, roleID domain.ID, permissions []string, requestID string) error {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE organization_id=$1 AND id=$2 AND system=false)`, org, roleID).Scan(&exists); err != nil || !exists {
		return errors.New("custom role not found")
	}
	if _, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, roleID); err != nil {
		return err
	}
	for _, permission := range permissions {
		tag, insertErr := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_id) SELECT $1,id FROM permissions WHERE name=$2`, roleID, permission)
		if insertErr != nil || tag.RowsAffected() != 1 {
			return errors.New("permission is invalid")
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome,metadata) VALUES($1,$2,'permission.changed','role',$3,$4,'success',jsonb_build_object('permissions',$5::text[]))`, org, user, roleID, requestID, permissions)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (c Commands) SetUserRoles(ctx context.Context, org, user, target domain.ID, roles []domain.ID, requestID string) error {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE organization_id=$1 AND id=$2 AND active)`, org, target).Scan(&exists); err != nil || !exists {
		return errors.New("user not found")
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1`, target); err != nil {
		return err
	}
	for _, role := range roles {
		tag, insertErr := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE id=$2 AND (organization_id=$3 OR organization_id IS NULL)`, target, role, org)
		if insertErr != nil || tag.RowsAffected() != 1 {
			return errors.New("role is invalid")
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) VALUES($1,$2,'user.roles_changed','user',$3,$4,'success')`, org, user, target, requestID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (c Commands) audit(ctx context.Context, org, user domain.ID, event, resource string, id domain.ID, requestID, outcome string, metadata map[string]any) error {
	data := []byte(`{}`)
	if metadata != nil {
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		data = encoded
	}
	_, err := c.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, org, user, event, resource, id, requestID, outcome, data)
	return err
}
