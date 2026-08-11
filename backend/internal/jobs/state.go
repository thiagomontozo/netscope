package jobs

import (
	"fmt"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

var transitions = map[domain.JobStatus]map[domain.JobStatus]bool{domain.JobPending: {domain.JobQueued: true, domain.JobRejected: true, domain.JobCancelled: true}, domain.JobQueued: {domain.JobAssigned: true, domain.JobCancelled: true, domain.JobTimedOut: true}, domain.JobAssigned: {domain.JobRunning: true, domain.JobQueued: true, domain.JobCancelled: true, domain.JobTimedOut: true}, domain.JobRunning: {domain.JobSucceeded: true, domain.JobFailed: true, domain.JobCancelled: true, domain.JobTimedOut: true}}

func CanTransition(from, to domain.JobStatus) bool { return transitions[from][to] }
func ValidateTransition(from, to domain.JobStatus) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("job transition %s to %s is not allowed", from, to)
	}
	return nil
}

type Transport interface {
	NotifyAvailable(organizationID domain.ID, agentID domain.ID) error
}
