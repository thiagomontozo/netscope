package correlation

import "github.com/thiagomontozo/netscope/backend/internal/domain"

type Input struct {
	Asset               domain.Asset
	ServiceObservation  *domain.Observation
	VulnerabilityID     *domain.ID
	ExposureObservation *domain.Observation
	IDSObservation      *domain.Observation
	KnownExploited      bool
}
type Candidate struct {
	Eligible           bool
	Confidence         domain.Confidence
	Reasons            []string
	Inputs             []string
	Rules              []string
	EvidenceIDs        []domain.ID
	CompromiseAsserted bool
}

func Correlate(input Input) Candidate {
	reasons := []string{}
	confidence := domain.ConfidenceLow
	if input.ServiceObservation != nil && input.VulnerabilityID != nil {
		reasons = append(reasons, "Observed service and vulnerability refer to the same asset context.")
		confidence = domain.ConfidenceMedium
	}
	if input.KnownExploited {
		reasons = append(reasons, "Known exploitation is a prioritization signal.")
	}
	if input.ExposureObservation != nil {
		reasons = append(reasons, "Public exposure was observed from an authorized sensor.")
	}
	if input.IDSObservation != nil {
		reasons = append(reasons, "An IDS observation is related but does not alone prove compromise.")
		if confidence == domain.ConfidenceMedium {
			confidence = domain.ConfidenceHigh
		}
	}
	inputs := []string{"asset:" + string(input.Asset.ID)}
	if input.ServiceObservation != nil {
		inputs = append(inputs, "service-observation:"+string(input.ServiceObservation.ID))
	}
	if input.VulnerabilityID != nil {
		inputs = append(inputs, "vulnerability:"+string(*input.VulnerabilityID))
	}
	if input.ExposureObservation != nil {
		inputs = append(inputs, "exposure-observation:"+string(input.ExposureObservation.ID))
	}
	if input.IDSObservation != nil {
		inputs = append(inputs, "ids-observation:"+string(input.IDSObservation.ID))
	}
	return Candidate{Eligible: len(reasons) > 0, Confidence: confidence, Reasons: reasons, Inputs: inputs, Rules: []string{"Correlate only organization-scoped records with matching asset/service context.", "Treat known exploitation and public exposure as priority context, not proof of compromise.", "Preserve inconclusive outcomes when observations conflict."}, CompromiseAsserted: false}
}
