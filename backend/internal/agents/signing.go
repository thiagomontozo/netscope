package agents

import (
	"context"

	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

// JobEnvelopeSigner is the transport-independent boundary for optional
// Ed25519 defense-in-depth signing. A deployment must keep the private key in a
// secret manager and publish the matching trust key during enrollment. The
// default control-plane runtime intentionally leaves this boundary disabled;
// mTLS, Authorized Scope and ScanGuard remain mandatory.
type JobEnvelopeSigner interface {
	Algorithm() string
	PublicKey() []byte
	Sign(context.Context, domain.JobEnvelope) (string, error)
}
