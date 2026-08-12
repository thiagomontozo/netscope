package agents

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type CertificateAuthority struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.Signer
	CertificatePEM []byte
}

func LoadCertificateAuthority(certificateFile, keyFile string) (*CertificateAuthority, error) {
	if certificateFile == "" || keyFile == "" {
		return nil, errors.New("agent certificate authority is not configured")
	}
	certPEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("agent CA PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("agent CA key must use PKCS#8")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("agent CA key is not a signing key")
	}
	return &CertificateAuthority{Certificate: certificate, PrivateKey: signer, CertificatePEM: certPEM}, nil
}
func (c *CertificateAuthority) SignCSR(organizationID, agentID domain.ID, csrPEM string) (certificatePEM []byte, fingerprint, serial string, expiresAt time.Time, err error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		err = errors.New("agent CSR is invalid")
		return
	}
	csr, parseErr := x509.ParseCertificateRequest(block.Bytes)
	if parseErr != nil || csr.CheckSignature() != nil {
		err = errors.New("agent CSR signature is invalid")
		return
	}
	serialNumber, randomErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if randomErr != nil {
		err = randomErr
		return
	}
	now := time.Now().UTC()
	expiresAt = now.Add(90 * 24 * time.Hour)
	identity, _ := url.Parse(fmt.Sprintf("spiffe://netscope/organizations/%s/agents/%s", organizationID, agentID))
	template := &x509.Certificate{SerialNumber: serialNumber, Subject: pkix.Name{CommonName: "NetScope Agent " + string(agentID)}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expiresAt, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}, BasicConstraintsValid: true}
	der, signErr := x509.CreateCertificate(rand.Reader, template, c.Certificate, csr.PublicKey, c.PrivateKey)
	if signErr != nil {
		err = signErr
		return
	}
	digest := sha256.Sum256(der)
	fingerprint = hex.EncodeToString(digest[:])
	serial = serialNumber.Text(16)
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return
}

type EnrollmentRequest struct {
	ProtocolVersion string `json:"protocolVersion"`
	EnrollmentToken string `json:"enrollmentToken"`
	AgentName       string `json:"agentName"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	AgentVersion    string `json:"agentVersion"`
	PublicIdentity  struct {
		CSRPEM string `json:"csrPem"`
	} `json:"publicIdentity"`
	CapabilitiesSummary []string          `json:"capabilitiesSummary"`
	Labels              map[string]string `json:"labels"`
	NetworkZone         string            `json:"networkZone"`
}
type EnrollmentResult struct {
	ProtocolVersion      string    `json:"protocolVersion"`
	AgentID              domain.ID `json:"agentId"`
	OrganizationID       domain.ID `json:"organizationId"`
	Status               string    `json:"status"`
	ControlPlaneIdentity struct {
		CACertificatePEM         string    `json:"caCertificatePem"`
		JobSigningKeyID          string    `json:"jobSigningKeyId,omitempty"`
		JobSigningAlgorithm      string    `json:"jobSigningAlgorithm,omitempty"`
		JobSigningPublicKey      string    `json:"jobSigningPublicKey,omitempty"`
		JobSigningKeyFingerprint string    `json:"jobSigningKeyFingerprint,omitempty"`
		JobSigningKeyIssuedAt    time.Time `json:"jobSigningKeyIssuedAt,omitempty"`
	} `json:"controlPlaneIdentity"`
	AgentCredential struct {
		CertificatePEM string    `json:"certificatePem"`
		ExpiresAt      time.Time `json:"expiresAt"`
	} `json:"agentCredential"`
	ServerTime time.Time `json:"serverTime"`
}
type EnrollmentService struct {
	Pool   *pgxpool.Pool
	CA     *CertificateAuthority
	Signer JobEnvelopeSigner
}

func (s EnrollmentService) Enroll(ctx context.Context, in EnrollmentRequest) (EnrollmentResult, error) {
	if s.CA == nil {
		return EnrollmentResult{}, errors.New("agent certificate authority is unavailable")
	}
	if err := RequireCompatible(in.ProtocolVersion); err != nil {
		return EnrollmentResult{}, err
	}
	if in.AgentName == "" || in.Hostname == "" || in.OS == "" || in.Architecture == "" || in.AgentVersion == "" {
		return EnrollmentResult{}, errors.New("agent identity fields are required")
	}
	tokenHash := sha256.Sum256([]byte(in.EnrollmentToken))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer tx.Rollback(ctx)
	var org, enrollmentID domain.ID
	err = tx.QueryRow(ctx, `SELECT id::text,organization_id::text FROM agent_enrollment_tokens WHERE token_hash=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, hex.EncodeToString(tokenHash[:])).Scan(&enrollmentID, &org)
	if err != nil {
		return EnrollmentResult{}, errors.New("enrollment token is invalid or expired")
	}
	capabilities, err := json.Marshal(in.CapabilitiesSummary)
	if err != nil {
		return EnrollmentResult{}, err
	}
	labels, err := json.Marshal(in.Labels)
	if err != nil {
		return EnrollmentResult{}, err
	}
	var agentID domain.ID
	compatibility := Compatibility(in.ProtocolVersion)
	err = tx.QueryRow(ctx, `INSERT INTO agents(organization_id,name,hostname,os,arch,version,status,capabilities,labels,network_zone,identity_fingerprint,protocol_version,compatibility_status) VALUES($1,$2,$3,$4,$5,$6,'PENDING',$7,$8,NULLIF($9,''),'pending',$10,$11) RETURNING id::text`, org, in.AgentName, in.Hostname, in.OS, in.Architecture, in.AgentVersion, capabilities, labels, in.NetworkZone, in.ProtocolVersion, compatibility).Scan(&agentID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	cert, fingerprint, serial, expires, err := s.CA.SignCSR(org, agentID, in.PublicIdentity.CSRPEM)
	if err != nil {
		return EnrollmentResult{}, err
	}
	signingKeyID := ""
	if s.Signer != nil {
		signingKeyID = s.Signer.KeyID()
	}
	_, err = tx.Exec(ctx, `UPDATE agents SET status='ONLINE',identity_fingerprint=$3,certificate_serial=$4,certificate_expires_at=$5,last_seen_at=now(),signing_key_id=NULLIF($6,'') WHERE organization_id=$1 AND id=$2`, org, agentID, fingerprint, serial, expires, signingKeyID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_certificates(organization_id,agent_id,serial_number,fingerprint,not_before,not_after,status) VALUES($1,$2,$3,$4,now()-interval '5 minutes',$5,'ACTIVE')`, org, agentID, serial, fingerprint, expires)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_enrollment_tokens SET used_at=now() WHERE id=$1`, enrollmentID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'agent.enrolled','agent',$2::text,'success',jsonb_build_object('fingerprint',$3::text))`, org, agentID, fingerprint)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return EnrollmentResult{}, err
	}
	result := EnrollmentResult{ProtocolVersion: domain.AgentProtocolVersion, AgentID: agentID, OrganizationID: org, Status: "ONLINE", ServerTime: time.Now().UTC()}
	result.ControlPlaneIdentity.CACertificatePEM = string(s.CA.CertificatePEM)
	if s.Signer != nil {
		result.ControlPlaneIdentity.JobSigningKeyID = s.Signer.KeyID()
		result.ControlPlaneIdentity.JobSigningAlgorithm = s.Signer.Algorithm()
		result.ControlPlaneIdentity.JobSigningPublicKey = base64.StdEncoding.EncodeToString(s.Signer.PublicKey())
		result.ControlPlaneIdentity.JobSigningKeyFingerprint = s.Signer.Fingerprint()
		result.ControlPlaneIdentity.JobSigningKeyIssuedAt = s.Signer.IssuedAt()
	}
	result.AgentCredential.CertificatePEM = string(cert)
	result.AgentCredential.ExpiresAt = expires
	return result, nil
}
