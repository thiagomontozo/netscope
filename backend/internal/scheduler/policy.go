package scheduler

import (
	"errors"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"time"
)

func ValidateFrequency(risk domain.RiskClass, frequency time.Duration) error {
	minimum := time.Minute
	if risk == domain.RiskControlledActive {
		minimum = 24 * time.Hour
	}
	if frequency < minimum {
		return errors.New("schedule frequency is below the minimum for this risk class")
	}
	return nil
}
