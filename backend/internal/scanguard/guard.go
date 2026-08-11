package scanguard

import (
	"context"
	"errors"
	"fmt"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/modules"
	"github.com/thiagomontozo/netscope/backend/internal/scopes"
	"time"
)

type PermissionChecker interface {
	Has(context.Context, domain.ID, domain.ID, string) (bool, error)
}
type AgentChecker interface {
	Supports(context.Context, domain.ID, domain.ID, []string) (bool, error)
}
type PolicyChecker interface {
	WithinMaintenanceWindow(context.Context, domain.ID, time.Time) bool
	AllowRate(context.Context, domain.ID, domain.ID, string) bool
	ConcurrentJobs(context.Context, domain.ID) (int, error)
}
type Request struct {
	OrganizationID domain.ID
	UserID         domain.ID
	AgentID        domain.ID
	Scope          domain.AuthorizedScope
	Adapter        modules.Adapter
	Parameters     []byte
	Now            time.Time
	MaxConcurrent  int
	Timeout        time.Duration
}
type Decision struct {
	Allowed          bool
	Code             string
	Reason           string
	NormalizedTarget string
	TimeoutAt        time.Time
}
type Guard struct {
	Permissions PermissionChecker
	Agents      AgentChecker
	Policies    PolicyChecker
}

func (g Guard) Authorize(ctx context.Context, req Request) (Decision, error) {
	deny := func(code, reason string) (Decision, error) { return Decision{Code: code, Reason: reason}, nil }
	if req.OrganizationID == "" || req.Scope.OrganizationID != req.OrganizationID {
		return deny("ORGANIZATION_MISMATCH", "scope does not belong to the active organization")
	}
	if !scopes.Active(req.Scope, req.Now) {
		return deny("SCOPE_NOT_AUTHORIZED", "scope is not approved and currently valid")
	}
	if !req.Adapter.Definition.Enabled {
		return deny("MODULE_DISABLED", "module is disabled")
	}
	supported := false
	for _, env := range req.Adapter.Definition.SupportedEnvironments {
		if env == req.Scope.Environment {
			supported = true
		}
	}
	if !supported {
		return deny("ENVIRONMENT_NOT_SUPPORTED", "module does not support the scope environment")
	}
	permission := "diagnostics.run"
	if req.Adapter.Definition.RiskClass == domain.RiskControlledActive {
		permission = "vulnerability.run"
	}
	if req.Scope.Environment == domain.EnvironmentPublic {
		permission = "public_scan.run"
	}
	ok, err := g.Permissions.Has(ctx, req.OrganizationID, req.UserID, permission)
	if err != nil {
		return Decision{}, fmt.Errorf("check permission: %w", err)
	}
	if !ok {
		return deny("PERMISSION_DENIED", "required permission is not granted")
	}
	ok, err = g.Agents.Supports(ctx, req.OrganizationID, req.AgentID, req.Adapter.Definition.RequiredCapabilities)
	if err != nil {
		return Decision{}, fmt.Errorf("check agent capabilities: %w", err)
	}
	if !ok {
		return deny("AGENT_INCOMPATIBLE", "agent lacks required capabilities")
	}
	if !g.Policies.WithinMaintenanceWindow(ctx, req.OrganizationID, req.Now) {
		return deny("OUTSIDE_MAINTENANCE_WINDOW", "execution is outside the allowed window")
	}
	if !g.Policies.AllowRate(ctx, req.OrganizationID, req.Scope.ID, req.Adapter.Definition.ID) {
		return deny("RATE_LIMITED", "scope and module rate limit reached")
	}
	count, err := g.Policies.ConcurrentJobs(ctx, req.OrganizationID)
	if err != nil {
		return Decision{}, err
	}
	if count >= req.MaxConcurrent {
		return deny("CONCURRENCY_LIMIT", "organization concurrent job limit reached")
	}
	if err := req.Adapter.Validator.Validate(req.Parameters); err != nil {
		return deny("INVALID_PARAMETERS", err.Error())
	}
	target, err := scopes.Normalize(req.Scope)
	if err != nil {
		return deny("INVALID_TARGET", "scope target cannot be normalized")
	}
	timeout := req.Timeout
	if timeout <= 0 || timeout > req.Adapter.Definition.DefaultTimeout {
		timeout = req.Adapter.Definition.DefaultTimeout
	}
	if timeout <= 0 {
		return Decision{}, errors.New("module timeout is not configured")
	}
	return Decision{Allowed: true, Code: "ALLOWED", Reason: "all Scan Guard checks passed", NormalizedTarget: target, TimeoutAt: req.Now.Add(timeout)}, nil
}
