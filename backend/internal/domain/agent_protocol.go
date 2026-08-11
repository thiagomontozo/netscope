package domain

import (
	"encoding/json"
	"time"
)

const AgentProtocolVersion = "1.0"

type AgentCompatibilityStatus string

const (
	AgentCompatible           AgentCompatibilityStatus = "COMPATIBLE"
	AgentUpgradeRecommended   AgentCompatibilityStatus = "UPGRADE_RECOMMENDED"
	AgentIncompatible         AgentCompatibilityStatus = "INCOMPATIBLE"
	AgentCompatibilityUnknown AgentCompatibilityStatus = "UNKNOWN"
)

type JobTarget struct {
	Type  ScopeType `json:"type"`
	Value string    `json:"value"`
}

type JobEnvelope struct {
	ProtocolVersion          string           `json:"protocolVersion"`
	JobID                    ID               `json:"jobId"`
	OrganizationID           ID               `json:"organizationId"`
	AgentID                  ID               `json:"agentId"`
	ModuleID                 string           `json:"moduleId"`
	ModuleVersionRequirement string           `json:"moduleVersionRequirement"`
	ScopeID                  ID               `json:"scopeId"`
	ScopeEnvironment         ScopeEnvironment `json:"scopeEnvironment"`
	AssetID                  *ID              `json:"assetId,omitempty"`
	ServiceID                *ID              `json:"serviceId,omitempty"`
	DiagnosticRunID          *ID              `json:"diagnosticRunId,omitempty"`
	VantagePointID           *ID              `json:"vantagePointId,omitempty"`
	Target                   JobTarget        `json:"target"`
	ValidatedParameters      json.RawMessage  `json:"validatedParameters"`
	RiskClass                RiskClass        `json:"riskClass"`
	AuthorizationReference   string           `json:"authorizationReference"`
	IssuedAt                 time.Time        `json:"issuedAt"`
	ExpiresAt                time.Time        `json:"expiresAt"`
	TimeoutSeconds           int              `json:"timeoutSeconds"`
	Nonce                    string           `json:"nonce"`
	SignatureAlgorithm       string           `json:"signatureAlgorithm,omitempty"`
	Signature                string           `json:"signature,omitempty"`
}
