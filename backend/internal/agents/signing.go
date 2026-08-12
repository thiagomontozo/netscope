package agents

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/thiagomontozo/netscope/backend/internal/canonicaljson"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

const SignatureAlgorithmEd25519 = "Ed25519"

// JobEnvelopeSigner keeps key custody separate from job delivery. Implementations
// must never expose or log private key bytes.
type JobEnvelopeSigner interface {
	Algorithm() string
	KeyID() string
	PublicKey() []byte
	Fingerprint() string
	IssuedAt() time.Time
	Sign(context.Context, domain.JobEnvelope) (string, error)
}

type Ed25519Signer struct {
	keyID       string
	private     ed25519.PrivateKey
	issuedAt    time.Time
	fingerprint string
}

func LoadEd25519Signer(path, keyID string) (*Ed25519Signer, error) {
	if path == "" || keyID == "" {
		return nil, errors.New("job signing key file and key ID are required")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read job signing key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("job signing key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("job signing key must use PKCS#8")
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("job signing key is not Ed25519")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	public := private.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	return &Ed25519Signer{keyID: keyID, private: private, issuedAt: info.ModTime().UTC(), fingerprint: hex.EncodeToString(digest[:])}, nil
}

func (s *Ed25519Signer) Algorithm() string { return SignatureAlgorithmEd25519 }
func (s *Ed25519Signer) KeyID() string     { return s.keyID }
func (s *Ed25519Signer) PublicKey() []byte {
	return append([]byte(nil), s.private.Public().(ed25519.PublicKey)...)
}
func (s *Ed25519Signer) Fingerprint() string { return s.fingerprint }
func (s *Ed25519Signer) IssuedAt() time.Time { return s.issuedAt }
func (s *Ed25519Signer) Sign(_ context.Context, envelope domain.JobEnvelope) (string, error) {
	payload, err := CanonicalJobPayload(envelope)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, payload)), nil
}

func CanonicalJobPayload(envelope domain.JobEnvelope) ([]byte, error) {
	parameters, err := canonicaljson.Canonicalize(envelope.ValidatedParameters)
	if err != nil {
		return nil, fmt.Errorf("decode validated parameters: %w", err)
	}
	payload := map[string]any{
		"agentId": envelope.AgentID, "authorizationReference": envelope.AuthorizationReference,
		"expiresAt": envelope.ExpiresAt.UTC().Format(time.RFC3339Nano), "issuedAt": envelope.IssuedAt.UTC().Format(time.RFC3339Nano),
		"jobId": envelope.JobID, "moduleId": envelope.ModuleID, "nonce": envelope.Nonce,
		"organizationId": envelope.OrganizationID, "protocolVersion": envelope.ProtocolVersion,
		"riskClass": envelope.RiskClass, "scopeEnvironment": envelope.ScopeEnvironment, "scopeId": envelope.ScopeID,
		"target":         map[string]any{"type": envelope.Target.Type, "value": envelope.Target.Value},
		"timeoutSeconds": envelope.TimeoutSeconds, "validatedParameters": json.RawMessage(parameters),
	}
	if envelope.AssetID != nil {
		payload["assetId"] = *envelope.AssetID
	}
	if envelope.ServiceID != nil {
		payload["serviceId"] = *envelope.ServiceID
	}
	return canonicaljson.Marshal(payload)
}
