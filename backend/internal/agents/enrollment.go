package agents

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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
	Token        string            `json:"token"`
	Name         string            `json:"name"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	Version      string            `json:"version"`
	Capabilities []string          `json:"capabilities"`
	Labels       map[string]string `json:"labels"`
	NetworkZone  string            `json:"networkZone"`
	CSRPEM       string            `json:"csrPem"`
}
type EnrollmentResult struct {
	AgentID          domain.ID `json:"agentId"`
	CertificatePEM   string    `json:"certificatePem"`
	CACertificatePEM string    `json:"caCertificatePem"`
	ExpiresAt        time.Time `json:"expiresAt"`
}
type EnrollmentService struct {
	Pool *pgxpool.Pool
	CA   *CertificateAuthority
}

func (s EnrollmentService) Enroll(ctx context.Context, in EnrollmentRequest) (EnrollmentResult, error) {
	if s.CA == nil {
		return EnrollmentResult{}, errors.New("agent certificate authority is unavailable")
	}
	tokenHash := sha256.Sum256([]byte(in.Token))
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
	capabilities, err := json.Marshal(in.Capabilities)
	if err != nil {
		return EnrollmentResult{}, err
	}
	labels, err := json.Marshal(in.Labels)
	if err != nil {
		return EnrollmentResult{}, err
	}
	var agentID domain.ID
	err = tx.QueryRow(ctx, `INSERT INTO agents(organization_id,name,hostname,os,arch,version,status,capabilities,labels,network_zone,identity_fingerprint) VALUES($1,$2,$3,$4,$5,$6,'PENDING',$7,$8,NULLIF($9,''),'pending') RETURNING id::text`, org, in.Name, in.Hostname, in.OS, in.Arch, in.Version, capabilities, labels, in.NetworkZone).Scan(&agentID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	cert, fingerprint, serial, expires, err := s.CA.SignCSR(org, agentID, in.CSRPEM)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE agents SET status='ONLINE',identity_fingerprint=$3,certificate_serial=$4,certificate_expires_at=$5,last_seen_at=now() WHERE organization_id=$1 AND id=$2`, org, agentID, fingerprint, serial, expires)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_enrollment_tokens SET used_at=now() WHERE id=$1`, enrollmentID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome,metadata) VALUES($1,$2,'agent.enrolled','agent',$2,'success',jsonb_build_object('fingerprint',$3))`, org, agentID, fingerprint)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{AgentID: agentID, CertificatePEM: string(cert), CACertificatePEM: string(s.CA.CertificatePEM), ExpiresAt: expires}, nil
}
