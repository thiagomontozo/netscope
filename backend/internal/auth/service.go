package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"time"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrMFARequired = errors.New("multi-factor authentication required")
var ErrMFAEnrollmentRequired = errors.New("multi-factor authentication enrollment required")

type Service struct {
	Pool       *pgxpool.Pool
	SessionTTL time.Duration
	MasterKey  []byte
}
type LoginResult struct {
	UserID         domain.ID
	OrganizationID domain.ID
	SessionToken   string
	MFAChallenge   string
	MFARequired    bool
}

func (s Service) Login(ctx context.Context, organizationSlug, email, password string) (LoginResult, error) {
	var user domain.User
	var requireOrganizationMFA, mfaEnabled bool
	var roles []string
	err := s.Pool.QueryRow(ctx, `SELECT u.id,u.organization_id,u.password_hash,u.active,o.require_mfa,coalesce(m.enabled,false),coalesce(array_agg(r.name) FILTER(WHERE r.name IS NOT NULL),'{}') FROM users u JOIN organizations o ON o.id=u.organization_id LEFT JOIN mfa_configurations m ON m.user_id=u.id LEFT JOIN user_roles ur ON ur.user_id=u.id LEFT JOIN roles r ON r.id=ur.role_id WHERE o.slug=$1 AND lower(u.email)=lower($2) GROUP BY u.id,o.require_mfa,m.enabled`, organizationSlug, email).Scan(&user.ID, &user.OrganizationID, &user.PasswordHash, &user.Active, &requireOrganizationMFA, &mfaEnabled, &roles)
	if err != nil || !user.Active || !VerifyPassword(password, user.PasswordHash) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if MFARequired(roles, requireOrganizationMFA) {
		if !mfaEnabled {
			return LoginResult{}, ErrMFAEnrollmentRequired
		}
		plain, digest, tokenErr := NewOpaqueToken(32)
		if tokenErr != nil {
			return LoginResult{}, tokenErr
		}
		_, tokenErr = s.Pool.Exec(ctx, `INSERT INTO mfa_login_challenges(organization_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, user.OrganizationID, user.ID, digest)
		if tokenErr != nil {
			return LoginResult{}, tokenErr
		}
		return LoginResult{UserID: user.ID, OrganizationID: user.OrganizationID, MFAChallenge: plain, MFARequired: true}, nil
	}
	return s.createSession(ctx, user.OrganizationID, user.ID)
}

func (s Service) createSession(ctx context.Context, organizationID, userID domain.ID) (LoginResult, error) {
	plain, digest, err := NewOpaqueToken(32)
	if err != nil {
		return LoginResult{}, err
	}
	expires := time.Now().UTC().Add(s.SessionTTL)
	_, err = s.Pool.Exec(ctx, `INSERT INTO sessions(organization_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, organizationID, userID, digest, expires)
	if err != nil {
		return LoginResult{}, err
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE users SET last_login_at=now(),updated_at=now() WHERE organization_id=$1 AND id=$2`, organizationID, userID)
	return LoginResult{UserID: userID, OrganizationID: organizationID, SessionToken: plain}, nil
}

func (s Service) CompleteMFA(ctx context.Context, challenge, code string) (LoginResult, error) {
	hash := sha256.Sum256([]byte(challenge))
	digest := hex.EncodeToString(hash[:])
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	defer tx.Rollback(ctx)
	var organizationID, userID domain.ID
	var encrypted []byte
	err = tx.QueryRow(ctx, `SELECT c.organization_id,c.user_id,m.encrypted_totp_secret FROM mfa_login_challenges c JOIN users u ON u.id=c.user_id AND u.organization_id=c.organization_id JOIN mfa_configurations m ON m.user_id=c.user_id AND m.organization_id=c.organization_id WHERE c.token_hash=$1 AND c.used_at IS NULL AND c.expires_at>now() AND u.active AND m.enabled FOR UPDATE`, digest).Scan(&organizationID, &userID, &encrypted)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	secret, err := DecryptSecret(s.MasterKey, encrypted)
	if err != nil {
		return LoginResult{}, err
	}
	if !VerifyTOTP(string(secret), code, time.Now().UTC()) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if _, err = tx.Exec(ctx, `UPDATE mfa_login_challenges SET used_at=now() WHERE token_hash=$1`, digest); err != nil {
		return LoginResult{}, err
	}
	plain, sessionDigest, err := NewOpaqueToken(32)
	if err != nil {
		return LoginResult{}, err
	}
	expires := time.Now().UTC().Add(s.SessionTTL)
	if _, err = tx.Exec(ctx, `INSERT INTO sessions(organization_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, organizationID, userID, sessionDigest, expires); err != nil {
		return LoginResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET last_login_at=now(),updated_at=now() WHERE organization_id=$1 AND id=$2`, organizationID, userID); err != nil {
		return LoginResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{UserID: userID, OrganizationID: organizationID, SessionToken: plain}, nil
}
func (s Service) Revoke(ctx context.Context, plain string) error {
	hash := sha256.Sum256([]byte(plain))
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, hex.EncodeToString(hash[:]))
	return err
}
func (s Service) RevokeAll(ctx context.Context, organizationID, userID domain.ID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE organization_id=$1 AND user_id=$2 AND revoked_at IS NULL`, organizationID, userID)
	return err
}
func (s Service) DisableUser(ctx context.Context, organizationID, userID domain.ID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE users SET active=false,disabled_at=now(),updated_at=now() WHERE organization_id=$1 AND id=$2`, organizationID, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE organization_id=$1 AND user_id=$2 AND revoked_at IS NULL`, organizationID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
