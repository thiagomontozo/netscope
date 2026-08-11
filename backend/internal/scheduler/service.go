package scheduler

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/scanguard"
	"time"
)

type Service struct {
	Pool          *pgxpool.Pool
	Store         database.ControlPlane
	Registry      *modules.Registry
	MaxConcurrent int
}
type dueSchedule struct {
	id, org                   domain.ID
	module                    string
	scope, agent, user, asset domain.ID
	service, vantage          *domain.ID
	parameters                json.RawMessage
	frequency                 int
}

func (s Service) RunOnce(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id::text,organization_id::text,module_id,scope_id::text,agent_id::text,created_by::text,asset_id::text,service_id::text,vantage_point_id::text,parameters,frequency_seconds FROM schedules WHERE enabled AND asset_id IS NOT NULL AND next_run_at<=now() ORDER BY next_run_at LIMIT 50`)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []dueSchedule{}
	for rows.Next() {
		var item dueSchedule
		if err = rows.Scan(&item.id, &item.org, &item.module, &item.scope, &item.agent, &item.user, &item.asset, &item.service, &item.vantage, &item.parameters, &item.frequency); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	guard := scanguard.Guard{Permissions: s.Store, Agents: s.Store, Policies: s.Store}
	for _, item := range items {
		adapter, ok := s.Registry.Get(item.module)
		if !ok {
			s.reject(ctx, item, "MODULE_UNKNOWN")
			continue
		}
		scope, scopeErr := s.Store.GetForOrganization(ctx, item.org, item.scope)
		if scopeErr != nil {
			s.reject(ctx, item, "SCOPE_NOT_FOUND")
			continue
		}
		parameters := item.parameters
		decision, decisionErr := guard.Authorize(ctx, scanguard.Request{OrganizationID: item.org, UserID: item.user, AgentID: item.agent, Scope: scope, Adapter: adapter, Parameters: parameters, Now: time.Now().UTC(), MaxConcurrent: s.MaxConcurrent})
		if decisionErr != nil {
			s.reject(ctx, item, "POLICY_ERROR")
			continue
		}
		if !decision.Allowed {
			s.reject(ctx, item, decision.Code)
			continue
		}
		if contextErr := s.Store.ValidateJobContext(ctx, item.org, item.asset, item.service, nil, item.vantage, item.agent); contextErr != nil {
			s.reject(ctx, item, "JOB_CONTEXT_INVALID")
			continue
		}
		jobID, idErr := domain.NewID()
		if idErr != nil {
			return idErr
		}
		now := time.Now().UTC()
		job := domain.AnalysisJob{ID: jobID, OrganizationID: item.org, ModuleID: item.module, AssetID: item.asset, ServiceID: item.service, VantagePointID: item.vantage, ScopeID: item.scope, AgentID: item.agent, RequestedBy: item.user, Parameters: parameters, RiskClass: adapter.Definition.RiskClass, Status: domain.JobQueued, CreatedAt: now, TimeoutAt: decision.TimeoutAt}
		if err = s.Store.CreateAuthorized(ctx, job, decision.NormalizedTarget); err != nil {
			continue
		}
		_, _ = s.Pool.Exec(ctx, `UPDATE schedules SET next_run_at=now()+make_interval(secs=>$3) WHERE organization_id=$1 AND id=$2`, item.org, item.id, item.frequency)
	}
	return nil
}
func (s Service) reject(ctx context.Context, item dueSchedule, code string) {
	_, _ = s.Pool.Exec(ctx, `UPDATE schedules SET next_run_at=now()+make_interval(secs=>$3) WHERE organization_id=$1 AND id=$2`, item.org, item.id, item.frequency)
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'job.rejected','schedule',$3,'rejected',jsonb_build_object('code',$4))`, item.org, item.user, item.id, code)
}
