package vulnerabilities

import (
	"context"
	"time"
)

type Enrichment struct {
	CVE         string
	Description string
	CVSS        map[string]float64
	References  []string
	FetchedAt   time.Time
	ExpiresAt   time.Time
}
type VulnerabilityEnrichmentProvider interface {
	Lookup(context.Context, string) (Enrichment, error)
}
type KnownExploited struct {
	CVE            string
	KnownExploited bool
	DateAdded      *time.Time
	RequiredAction string
	DueDate        *time.Time
}
type KnownExploitedProvider interface {
	Lookup(context.Context, string) (KnownExploited, error)
}
