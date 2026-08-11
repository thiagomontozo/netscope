package agents

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

func Compatibility(version string) domain.AgentCompatibilityStatus {
	major, minor, ok := protocolParts(version)
	if !ok {
		return domain.AgentCompatibilityUnknown
	}
	controlMajor, controlMinor, _ := protocolParts(domain.AgentProtocolVersion)
	if major != controlMajor {
		return domain.AgentIncompatible
	}
	if minor > controlMinor {
		return domain.AgentUpgradeRecommended
	}
	return domain.AgentCompatible
}

func RequireCompatible(version string) error {
	status := Compatibility(version)
	if status == domain.AgentIncompatible || status == domain.AgentCompatibilityUnknown {
		return fmt.Errorf("agent protocol %q is incompatible with control plane protocol %s", version, domain.AgentProtocolVersion)
	}
	return nil
}

func protocolParts(version string) (int, int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	return major, minor, majorErr == nil && minorErr == nil && major >= 0 && minor >= 0
}

type PresencePolicy struct {
	HeartbeatIntervalSeconds int
	DegradedAfterMisses      int
	OfflineAfterMisses       int
}

func DefaultPresencePolicy() PresencePolicy {
	return PresencePolicy{HeartbeatIntervalSeconds: 30, DegradedAfterMisses: 3, OfflineAfterMisses: 6}
}

func UpdatePresence(ctx context.Context, pool *pgxpool.Pool, policy PresencePolicy) error {
	degradedAfter := policy.HeartbeatIntervalSeconds * policy.DegradedAfterMisses
	offlineAfter := policy.HeartbeatIntervalSeconds * policy.OfflineAfterMisses
	_, err := pool.Exec(ctx, `UPDATE agents SET status=CASE WHEN last_seen_at < now()-make_interval(secs=>$1) THEN 'OFFLINE' WHEN last_seen_at < now()-make_interval(secs=>$2) THEN 'DEGRADED' ELSE 'ONLINE' END WHERE status IN ('ONLINE','DEGRADED','OFFLINE') AND last_seen_at IS NOT NULL`, offlineAfter, degradedAfter)
	return err
}
