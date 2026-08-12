package agents

import (
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"testing"
)

func TestCompatibilityMatrix(t *testing.T) {
	cases := map[string]domain.AgentCompatibilityStatus{"1.0": domain.AgentCompatible, "1.1": domain.AgentUpgradeRecommended, "0.9": domain.AgentIncompatible, "2.0": domain.AgentIncompatible, "bad": domain.AgentCompatibilityUnknown}
	for version, want := range cases {
		if got := Compatibility(version); got != want {
			t.Errorf("Compatibility(%q)=%s want %s", version, got, want)
		}
	}
}
