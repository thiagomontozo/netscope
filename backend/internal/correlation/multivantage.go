package correlation

import "github.com/thiagomontozo/netscope/backend/internal/domain"

type VantageObservation struct {
	VantagePointID domain.ID               `json:"vantagePointId"`
	VantageName    string                  `json:"vantageName"`
	Status         domain.NormalizedStatus `json:"status"`
	Reachable      *bool                   `json:"reachable,omitempty"`
	LatencyMS      *float64                `json:"latencyMs,omitempty"`
	EvidenceIDs    []domain.ID             `json:"evidenceIds"`
}
type VantageSummary struct {
	Status       domain.NormalizedStatus `json:"status"`
	Confidence   domain.Confidence       `json:"confidence"`
	Explanation  string                  `json:"explanation"`
	Observations []VantageObservation    `json:"observations"`
}

func SummarizeVantages(observations []VantageObservation) VantageSummary {
	if len(observations) == 0 {
		return VantageSummary{Status: domain.StatusInconclusive, Confidence: domain.ConfidenceLow, Explanation: "Connectivity has not been observed from any vantage point."}
	}
	reachable, unreachable, unknown := 0, 0, 0
	for _, observation := range observations {
		if observation.Reachable == nil {
			unknown++
		} else if *observation.Reachable {
			reachable++
		} else {
			unreachable++
		}
	}
	result := VantageSummary{Status: domain.StatusInconclusive, Confidence: domain.ConfidenceMedium, Observations: observations}
	switch {
	case reachable > 0 && unreachable > 0:
		result.Status = domain.StatusAttention
		result.Explanation = "The service is reachable from some vantage points but unreachable from others. The issue may be path- or location-specific."
	case reachable > 0 && unreachable == 0 && unknown == 0:
		result.Status = domain.StatusHealthy
		result.Confidence = domain.ConfidenceHigh
		result.Explanation = "All reporting vantage points obtained a direct successful response. This confirms reachability only from those locations and at those times."
	case unreachable > 0 && reachable == 0 && unknown == 0:
		result.Status = domain.StatusWarning
		result.Explanation = "No reporting vantage point confirmed reachability. Service unavailability is probable, but target and monitoring-location evidence should still be reviewed."
	default:
		result.Explanation = "Available vantage-point evidence is incomplete or conflicting; connectivity remains inconclusive."
	}
	return result
}
