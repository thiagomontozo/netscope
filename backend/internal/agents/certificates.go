package agents

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type CertificatePolicy struct{ Lifetime, RotationBeforeExpiration, RotationGracePeriod time.Duration }

func DefaultCertificatePolicy() CertificatePolicy {
	return CertificatePolicy{Lifetime: 90 * 24 * time.Hour, RotationBeforeExpiration: 14 * 24 * time.Hour, RotationGracePeriod: 24 * time.Hour}
}

type RotationService struct {
	Pool   *pgxpool.Pool
	CA     *CertificateAuthority
	Policy CertificatePolicy
}
type RotationResult struct {
	CertificateID  domain.ID `json:"certificateId"`
	CertificatePEM string    `json:"certificatePem"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Fingerprint    string    `json:"fingerprint"`
	SerialNumber   string    `json:"serialNumber"`
}

func (s RotationService) Request(ctx context.Context, organizationID, agentID domain.ID, csrPEM string) (RotationResult, error) {
	if s.CA == nil || csrPEM == "" {
		return RotationResult{}, errors.New("certificate rotation is unavailable")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RotationResult{}, err
	}
	defer tx.Rollback(ctx)
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM agents WHERE organization_id=$1 AND id=$2 FOR UPDATE`, organizationID, agentID).Scan(&status); err != nil || status == "REVOKED" {
		return RotationResult{}, errors.New("agent is not eligible for rotation")
	}
	certificate, fingerprint, serial, expires, err := s.CA.SignCSR(organizationID, agentID, csrPEM)
	if err != nil {
		return RotationResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_certificates SET status='REVOKED',revoked_at=now() WHERE organization_id=$1 AND agent_id=$2 AND status='ROTATING'`, organizationID, agentID); err != nil {
		return RotationResult{}, err
	}
	var certificateID domain.ID
	err = tx.QueryRow(ctx, `INSERT INTO agent_certificates(organization_id,agent_id,serial_number,fingerprint,not_before,not_after,status) VALUES($1,$2,$3,$4,now()-interval '5 minutes',$5,'ROTATING') RETURNING id::text`, organizationID, agentID, serial, fingerprint, expires).Scan(&certificateID)
	if err != nil {
		return RotationResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE agents SET certificate_rotation_status='ISSUED' WHERE organization_id=$1 AND id=$2`, organizationID, agentID)
	if err != nil {
		return RotationResult{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome) VALUES($1,$2,'agent.certificate_rotation_requested','agent',$2::text,'success'),($1,$2,'agent.certificate_issued','agent_certificate',$3::text,'success')`, organizationID, agentID, certificateID)
	if err != nil {
		return RotationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RotationResult{}, err
	}
	return RotationResult{CertificateID: certificateID, CertificatePEM: string(certificate), ExpiresAt: expires, Fingerprint: fingerprint, SerialNumber: serial}, nil
}

func (s RotationService) Confirm(ctx context.Context, organizationID, agentID, certificateID domain.ID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var fingerprint, serial string
	var expires time.Time
	err = tx.QueryRow(ctx, `UPDATE agent_certificates SET status='ACTIVE' WHERE organization_id=$1 AND agent_id=$2 AND id=$3 AND status='ROTATING' RETURNING fingerprint,serial_number,not_after`, organizationID, agentID, certificateID).Scan(&fingerprint, &serial, &expires)
	if err != nil {
		return errors.New("pending rotation certificate was not found")
	}
	_, err = tx.Exec(ctx, `UPDATE agent_certificates SET status='SUPERSEDED',replaced_by=$3 WHERE organization_id=$1 AND agent_id=$2 AND id<>$3 AND status='ACTIVE'; UPDATE agents SET identity_fingerprint=$4,certificate_serial=$5,certificate_expires_at=$6,certificate_rotation_status='GRACE_PERIOD' WHERE organization_id=$1 AND id=$2`, organizationID, agentID, certificateID, fingerprint, serial, expires)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_agent_id,event_type,resource_type,resource_id,outcome) VALUES($1,$2,'agent.certificate_rotated','agent_certificate',$3::text,'success')`, organizationID, agentID, certificateID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
