package artifacts

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	DirectionToAgent   = "CONTROL_PLANE_TO_AGENT"
	DirectionFromAgent = "AGENT_TO_CONTROL_PLANE"
	PurposeDownload    = "DOWNLOAD"
	PurposeUpload      = "UPLOAD"
)

var ErrChecksumMismatch = errors.New("ARTIFACT_CHECKSUM_MISMATCH")
var ErrSizeLimit = errors.New("ARTIFACT_SIZE_LIMIT_EXCEEDED")

type Manifest struct {
	ProtocolVersion   string     `json:"protocolVersion"`
	ArtifactID        string     `json:"artifactId"`
	OrganizationID    string     `json:"organizationId"`
	JobID             *string    `json:"jobId,omitempty"`
	Type              string     `json:"type"`
	Direction         string     `json:"direction"`
	ContentType       string     `json:"contentType"`
	OriginalName      string     `json:"originalName,omitempty"`
	SizeBytes         int64      `json:"sizeBytes"`
	SHA256            string     `json:"sha256"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"createdAt"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	UploadedByAgentID *string    `json:"uploadedByAgentId,omitempty"`
}

type TransferClaims struct {
	ArtifactID     string `json:"artifactId"`
	OrganizationID string `json:"organizationId"`
	AgentID        string `json:"agentId"`
	JobID          string `json:"jobId,omitempty"`
	Purpose        string `json:"purpose"`
	ExpiresAt      int64  `json:"expiresAt"`
	Nonce          string `json:"nonce"`
}

type TokenManager struct {
	Key []byte
	TTL time.Duration
	Now func() time.Time
}

func (m TokenManager) Issue(claims TransferClaims) (string, error) {
	if len(m.Key) < 32 {
		return "", errors.New("artifact token key must contain at least 32 bytes")
	}
	if claims.ArtifactID == "" || claims.OrganizationID == "" || claims.AgentID == "" || (claims.Purpose != PurposeDownload && claims.Purpose != PurposeUpload) {
		return "", errors.New("artifact token claims are incomplete")
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	ttl := m.TTL
	if ttl <= 0 || ttl > 15*time.Minute {
		ttl = 5 * time.Minute
	}
	claims.ExpiresAt = now.Add(ttl).Unix()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	claims.Nonce = hex.EncodeToString(nonce)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.Key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m TokenManager) Verify(token string, expected TransferClaims) (TransferClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return TransferClaims{}, errors.New("artifact token format is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TransferClaims{}, errors.New("artifact token signature is invalid")
	}
	mac := hmac.New(sha256.New, m.Key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return TransferClaims{}, errors.New("artifact token signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return TransferClaims{}, errors.New("artifact token payload is invalid")
	}
	var claims TransferClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil {
		return TransferClaims{}, errors.New("artifact token payload is invalid")
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	if claims.ExpiresAt <= now.Unix() || claims.ArtifactID != expected.ArtifactID || claims.OrganizationID != expected.OrganizationID || claims.AgentID != expected.AgentID || claims.JobID != expected.JobID || claims.Purpose != expected.Purpose {
		return TransferClaims{}, errors.New("artifact token scope or expiry is invalid")
	}
	return claims, nil
}

func CopyVerified(_ context.Context, destination io.Writer, source io.Reader, expectedSize, maximum int64, expectedSHA256 string) (int64, error) {
	if expectedSize < 0 || maximum < 1 || expectedSize > maximum {
		return 0, ErrSizeLimit
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: source, N: maximum + 1}
	written, err := io.Copy(io.MultiWriter(destination, hash), limited)
	if err != nil {
		return written, err
	}
	if written > maximum {
		return written, ErrSizeLimit
	}
	if expectedSize != written {
		return written, fmt.Errorf("artifact final size %s differs from manifest %s", strconv.FormatInt(written, 10), strconv.FormatInt(expectedSize, 10))
	}
	if !hmac.Equal([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(strings.ToLower(expectedSHA256))) {
		return written, ErrChecksumMismatch
	}
	return written, nil
}
