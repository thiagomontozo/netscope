package diagnostics

import "github.com/thiagomontozo/netscope/backend/internal/domain"

type RouteComparison struct {
	Status             domain.RouteComparisonStatus `json:"status"`
	FirstDivergenceHop *int                         `json:"firstDivergenceHop,omitempty"`
	Summary            string                       `json:"summary"`
	Confidence         domain.Confidence            `json:"confidence"`
}

func CompareRoutes(previous, current []domain.RouteHop) RouteComparison {
	if len(previous) == 0 || len(current) == 0 {
		return RouteComparison{Status: domain.RouteInconclusive, Summary: "One or both route snapshots are incomplete; a path change cannot be confirmed.", Confidence: domain.ConfidenceLow}
	}
	limit := len(previous)
	if len(current) < limit {
		limit = len(current)
	}
	for index := 0; index < limit; index++ {
		a, b := previous[index], current[index]
		if a.TimedOut || b.TimedOut {
			hop := index + 1
			return RouteComparison{Status: domain.RoutePartiallyChanged, FirstDivergenceHop: &hop, Summary: "The paths differ or contain timeouts from the indicated hop. This does not by itself identify an incident or root cause.", Confidence: domain.ConfidenceLow}
		}
		if a.Address != b.Address {
			hop := index + 1
			return RouteComparison{Status: domain.RouteChanged, FirstDivergenceHop: &hop, Summary: "The observed paths first diverge at the indicated hop. Routing changes can be normal and require contextual evidence.", Confidence: domain.ConfidenceMedium}
		}
	}
	if len(previous) != len(current) {
		hop := limit + 1
		return RouteComparison{Status: domain.RoutePartiallyChanged, FirstDivergenceHop: &hop, Summary: "The common path is unchanged, but the snapshots contain a different number of hops.", Confidence: domain.ConfidenceMedium}
	}
	return RouteComparison{Status: domain.RouteUnchanged, Summary: "No address-level path change was observed between these snapshots. This does not prove path stability outside the observation window.", Confidence: domain.ConfidenceHigh}
}
