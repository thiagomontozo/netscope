package domain

import (
	"encoding/json"
	"time"
)

type ID string

type NormalizedStatus string

const (
	StatusHealthy       NormalizedStatus = "HEALTHY"
	StatusInformational NormalizedStatus = "INFORMATIONAL"
	StatusAttention     NormalizedStatus = "ATTENTION"
	StatusWarning       NormalizedStatus = "WARNING"
	StatusCritical      NormalizedStatus = "CRITICAL"
	StatusInconclusive  NormalizedStatus = "INCONCLUSIVE"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

type Organization struct {
	ID        ID        `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Timezone  string    `json:"timezone"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
type User struct {
	ID             ID         `json:"id"`
	OrganizationID ID         `json:"organizationId"`
	Name           string     `json:"name"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"`
	Active         bool       `json:"active"`
	LastLoginAt    *time.Time `json:"lastLoginAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	DisabledAt     *time.Time `json:"disabledAt"`
}

type ScopeType string
type ScopeEnvironment string
type ScopeStatus string

const (
	ScopeHostname       ScopeType        = "HOSTNAME"
	ScopeIP             ScopeType        = "IP"
	ScopeCIDR           ScopeType        = "CIDR"
	ScopeURL            ScopeType        = "URL"
	EnvironmentInternal ScopeEnvironment = "INTERNAL"
	EnvironmentPublic   ScopeEnvironment = "PUBLIC"
	ScopePending        ScopeStatus      = "PENDING"
	ScopeVerified       ScopeStatus      = "VERIFIED"
	ScopeApproved       ScopeStatus      = "APPROVED"
	ScopeRevoked        ScopeStatus      = "REVOKED"
	ScopeExpired        ScopeStatus      = "EXPIRED"
)

type AuthorizedScope struct {
	ID               ID               `json:"id"`
	OrganizationID   ID               `json:"organizationId"`
	Type             ScopeType        `json:"type"`
	Value            string           `json:"value"`
	Environment      ScopeEnvironment `json:"environment"`
	Status           ScopeStatus      `json:"status"`
	VerificationType string           `json:"verificationType"`
	VerifiedAt       *time.Time       `json:"verifiedAt"`
	VerifiedBy       *ID              `json:"verifiedBy"`
	ValidFrom        time.Time        `json:"validFrom"`
	ValidUntil       time.Time        `json:"validUntil"`
	Notes            string           `json:"notes"`
	CreatedAt        time.Time        `json:"createdAt"`
}

type Asset struct {
	ID             ID               `json:"id"`
	OrganizationID ID               `json:"organizationId"`
	Name           string           `json:"name"`
	Type           string           `json:"type"`
	Hostname       string           `json:"hostname"`
	IPAddress      string           `json:"ipAddress"`
	Environment    ScopeEnvironment `json:"environment"`
	Criticality    string           `json:"criticality"`
	Owner          string           `json:"owner"`
	Description    string           `json:"description"`
	FirstSeenAt    time.Time        `json:"firstSeenAt"`
	LastSeenAt     time.Time        `json:"lastSeenAt"`
	Status         NormalizedStatus `json:"status"`
	CreatedAt      time.Time        `json:"createdAt"`
	UpdatedAt      time.Time        `json:"updatedAt"`
}

type RiskClass string

const (
	RiskPassive          RiskClass = "PASSIVE"
	RiskSafeActive       RiskClass = "SAFE_ACTIVE"
	RiskControlledActive RiskClass = "CONTROLLED_ACTIVE"
)

type ModuleDefinition struct {
	ID                    string             `json:"id"`
	Name                  string             `json:"name"`
	Version               string             `json:"version"`
	Category              string             `json:"category"`
	RiskClass             RiskClass          `json:"riskClass"`
	SupportedEnvironments []ScopeEnvironment `json:"supportedEnvironments"`
	RequiredCapabilities  []string           `json:"requiredCapabilities"`
	DefaultTimeout        time.Duration      `json:"defaultTimeout"`
	InputSchema           json.RawMessage    `json:"inputSchema"`
	ResultSchema          json.RawMessage    `json:"resultSchema"`
	Enabled               bool               `json:"enabled"`
}

type JobStatus string

const (
	JobPending   JobStatus = "PENDING"
	JobQueued    JobStatus = "QUEUED"
	JobAssigned  JobStatus = "ASSIGNED"
	JobRunning   JobStatus = "RUNNING"
	JobSucceeded JobStatus = "SUCCEEDED"
	JobFailed    JobStatus = "FAILED"
	JobCancelled JobStatus = "CANCELLED"
	JobTimedOut  JobStatus = "TIMED_OUT"
	JobRejected  JobStatus = "REJECTED"
)

type AnalysisJob struct {
	ID             ID              `json:"id"`
	OrganizationID ID              `json:"organizationId"`
	ModuleID       string          `json:"moduleId"`
	AssetID        ID              `json:"assetId"`
	ScopeID        ID              `json:"scopeId"`
	AgentID        ID              `json:"agentId"`
	RequestedBy    ID              `json:"requestedBy"`
	Parameters     json.RawMessage `json:"parameters"`
	RiskClass      RiskClass       `json:"riskClass"`
	Status         JobStatus       `json:"status"`
	CreatedAt      time.Time       `json:"createdAt"`
	QueuedAt       *time.Time      `json:"queuedAt"`
	StartedAt      *time.Time      `json:"startedAt"`
	CompletedAt    *time.Time      `json:"completedAt"`
	TimeoutAt      time.Time       `json:"timeoutAt"`
}

type Observation struct {
	ID              ID               `json:"id"`
	OrganizationID  ID               `json:"organizationId"`
	AssetID         ID               `json:"assetId"`
	ModuleID        string           `json:"moduleId"`
	JobID           ID               `json:"jobId"`
	Category        string           `json:"category"`
	Status          NormalizedStatus `json:"status"`
	Severity        string           `json:"severity"`
	Confidence      Confidence       `json:"confidence"`
	Title           string           `json:"title"`
	Summary         string           `json:"summary"`
	Meaning         string           `json:"meaning"`
	Impact          string           `json:"impact"`
	SuggestedAction string           `json:"suggestedAction"`
	ObservedAt      time.Time        `json:"observedAt"`
	EvidenceCount   int              `json:"evidenceCount"`
	RawReference    string           `json:"rawReference,omitempty"`
}
type Finding struct {
	ID                  ID         `json:"id"`
	OrganizationID      ID         `json:"organizationId"`
	AssetID             ID         `json:"assetId"`
	SourceObservationID ID         `json:"sourceObservationId"`
	Category            string     `json:"category"`
	Severity            string     `json:"severity"`
	Priority            string     `json:"priority"`
	Confidence          Confidence `json:"confidence"`
	Title               string     `json:"title"`
	Description         string     `json:"description"`
	Remediation         string     `json:"remediation"`
	Status              string     `json:"status"`
	FirstSeenAt         time.Time  `json:"firstSeenAt"`
	LastSeenAt          time.Time  `json:"lastSeenAt"`
	ResolvedAt          *time.Time `json:"resolvedAt"`
	ResolvedBy          *ID        `json:"resolvedBy"`
}
type Evidence struct {
	ID             ID              `json:"id"`
	OrganizationID ID              `json:"organizationId"`
	JobID          ID              `json:"jobId"`
	ObservationID  *ID             `json:"observationId"`
	FindingID      *ID             `json:"findingId"`
	Source         string          `json:"source"`
	ContentType    string          `json:"contentType"`
	Summary        string          `json:"summary"`
	StorageKey     string          `json:"storageKey,omitempty"`
	StructuredData json.RawMessage `json:"structuredData,omitempty"`
	Checksum       string          `json:"checksum,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
}

type Agent struct {
	ID             ID                `json:"id"`
	OrganizationID ID                `json:"organizationId"`
	Name           string            `json:"name"`
	Hostname       string            `json:"hostname"`
	OS             string            `json:"os"`
	Arch           string            `json:"arch"`
	Version        string            `json:"version"`
	Status         string            `json:"status"`
	LastSeenAt     *time.Time        `json:"lastSeenAt"`
	RegisteredAt   time.Time         `json:"registeredAt"`
	Capabilities   []string          `json:"capabilities"`
	Labels         map[string]string `json:"labels"`
	NetworkZone    string            `json:"networkZone"`
	Fingerprint    string            `json:"fingerprint"`
}

type JobEnvelope struct {
	JobID           ID              `json:"jobId"`
	ModuleID        string          `json:"moduleId"`
	ScopeID         ID              `json:"scopeId"`
	TargetReference string          `json:"targetReference"`
	Parameters      json.RawMessage `json:"validatedParameters"`
	IssuedAt        time.Time       `json:"issuedAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	OrganizationID  ID              `json:"organizationId"`
	AgentID         ID              `json:"agentId"`
	Nonce           string          `json:"nonce"`
	RiskClass       RiskClass       `json:"riskClass"`
	Signature       string          `json:"signature,omitempty"`
}
