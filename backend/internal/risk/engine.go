package risk

import "strings"

type Context struct {
	Severity         string `json:"severity"`
	KnownExploited   bool   `json:"knownExploited"`
	PublicExposure   bool   `json:"publicExposure"`
	AssetCriticality string `json:"assetCriticality"`
	ServicePresent   bool   `json:"servicePresent"`
	Confidence       string `json:"confidence"`
	AgeDays          int    `json:"ageDays"`
}
type Result struct {
	Priority string   `json:"priority"`
	Factors  []string `json:"factors"`
}

func Evaluate(c Context) Result {
	levels := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	score := 1
	switch strings.ToUpper(c.Severity) {
	case "LOW", "INFORMATIONAL":
		score = 0
	case "HIGH":
		score = 2
	case "CRITICAL":
		score = 3
	}
	factors := []string{"Base priority follows normalized severity."}
	if c.KnownExploited && c.ServicePresent {
		score++
		factors = append(factors, "Known exploitation and observed affected service raise priority.")
	}
	if c.PublicExposure {
		score++
		factors = append(factors, "Approved public exposure raises priority.")
	}
	if strings.EqualFold(c.AssetCriticality, "CRITICAL") {
		score++
		factors = append(factors, "Critical asset context raises priority.")
	}
	if strings.EqualFold(c.Confidence, "LOW") {
		score--
		factors = append(factors, "Low confidence limits priority pending confirmation.")
	}
	if !c.ServicePresent {
		score--
		factors = append(factors, "No observed affected service reduces immediate priority.")
	}
	if c.AgeDays > 30 {
		score--
		factors = append(factors, "Stale evidence reduces priority pending refresh.")
	}
	if score < 0 {
		score = 0
	}
	if score > 3 {
		score = 3
	}
	return Result{Priority: levels[score], Factors: factors}
}
