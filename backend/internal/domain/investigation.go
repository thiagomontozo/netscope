package domain

import (
	"encoding/json"
	"time"
)

type VantagePoint struct {
	ID             ID                `json:"id"`
	OrganizationID ID                `json:"organizationId"`
	Name           string            `json:"name"`
	AgentID        *ID               `json:"agentId,omitempty"`
	Site           string            `json:"site,omitempty"`
	NetworkZone    string            `json:"networkZone,omitempty"`
	Environment    ScopeEnvironment  `json:"environment"`
	Labels         map[string]string `json:"labels"`
	Active         bool              `json:"active"`
}

type NetworkService struct {
	ID             ID               `json:"id"`
	OrganizationID ID               `json:"organizationId"`
	AssetID        ID               `json:"assetId"`
	Protocol       string           `json:"protocol"`
	Port           int              `json:"port"`
	Name           string           `json:"name"`
	Product        string           `json:"product,omitempty"`
	Version        string           `json:"version,omitempty"`
	PublicExposure bool             `json:"publicExposure"`
	FirstSeenAt    time.Time        `json:"firstSeenAt"`
	LastSeenAt     time.Time        `json:"lastSeenAt"`
	Status         NormalizedStatus `json:"status"`
}

type DiagnosticRun struct {
	ID             ID         `json:"id"`
	OrganizationID ID         `json:"organizationId"`
	AssetID        ID         `json:"assetId"`
	ServiceID      *ID        `json:"serviceId,omitempty"`
	RequestedBy    ID         `json:"requestedBy"`
	Profile        string     `json:"profile"`
	Status         string     `json:"status"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	Summary        string     `json:"summary"`
	Confidence     Confidence `json:"confidence"`
}

type IncidentStatus string
type RootCauseStatus string
type IncidentEvidenceRole string

const (
	IncidentOpen          IncidentStatus       = "OPEN"
	IncidentInvestigating IncidentStatus       = "INVESTIGATING"
	IncidentMonitoring    IncidentStatus       = "MONITORING"
	IncidentResolved      IncidentStatus       = "RESOLVED"
	IncidentClosed        IncidentStatus       = "CLOSED"
	RootCauseUnknown      RootCauseStatus      = "UNKNOWN"
	RootCauseSuspected    RootCauseStatus      = "SUSPECTED"
	RootCauseIdentified   RootCauseStatus      = "IDENTIFIED"
	RootCauseInconclusive RootCauseStatus      = "INCONCLUSIVE"
	EvidenceKey           IncidentEvidenceRole = "KEY_EVIDENCE"
	EvidenceSupporting    IncidentEvidenceRole = "SUPPORTING_EVIDENCE"
	EvidenceContext       IncidentEvidenceRole = "CONTEXT"
)

type Incident struct {
	ID              ID              `json:"id"`
	OrganizationID  ID              `json:"organizationId"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Status          IncidentStatus  `json:"status"`
	Severity        string          `json:"severity,omitempty"`
	StartedAt       *time.Time      `json:"startedAt,omitempty"`
	DetectedAt      time.Time       `json:"detectedAt"`
	ResolvedAt      *time.Time      `json:"resolvedAt,omitempty"`
	CreatedBy       ID              `json:"createdBy"`
	AssignedTo      *ID             `json:"assignedTo,omitempty"`
	PrimaryAssetID  *ID             `json:"primaryAssetId,omitempty"`
	RootCauseStatus RootCauseStatus `json:"rootCauseStatus"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

type IncidentEvent struct {
	ID             ID               `json:"id"`
	OrganizationID ID               `json:"organizationId"`
	IncidentID     ID               `json:"incidentId"`
	EventType      string           `json:"eventType"`
	Title          string           `json:"title"`
	Description    string           `json:"description"`
	Status         NormalizedStatus `json:"status"`
	Confidence     Confidence       `json:"confidence"`
	SourceType     string           `json:"sourceType"`
	SourceID       string           `json:"sourceId,omitempty"`
	OccurredAt     time.Time        `json:"occurredAt"`
}

type RouteHop struct {
	Sequence         int             `json:"sequence"`
	Address          string          `json:"address,omitempty"`
	Hostname         string          `json:"hostname,omitempty"`
	LatencySamplesMS json.RawMessage `json:"latencySamplesMs"`
	TimedOut         bool            `json:"timedOut"`
}

type RouteComparisonStatus string

const (
	RouteUnchanged        RouteComparisonStatus = "UNCHANGED"
	RouteChanged          RouteComparisonStatus = "CHANGED"
	RoutePartiallyChanged RouteComparisonStatus = "PARTIALLY_CHANGED"
	RouteInconclusive     RouteComparisonStatus = "INCONCLUSIVE"
)
