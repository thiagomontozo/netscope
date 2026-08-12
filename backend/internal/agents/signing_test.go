package agents

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

func testEnvelope() domain.JobEnvelope {
	return domain.JobEnvelope{ProtocolVersion: "1.0", JobID: "33333333-3333-4333-8333-333333333333", OrganizationID: "22222222-2222-4222-8222-222222222222", AgentID: "11111111-1111-4111-8111-111111111111", ModuleID: "mock.safe", ScopeID: "44444444-4444-4444-8444-444444444444", ScopeEnvironment: "INTERNAL", Target: domain.JobTarget{Type: "HOSTNAME", Value: "fixture.test.invalid"}, ValidatedParameters: []byte(`{"z":2,"mode":"synthetic","nested":{"b":true,"a":null}}`), RiskClass: "PASSIVE", AuthorizationReference: "test-only:fixture", IssuedAt: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 11, 12, 5, 0, 0, time.UTC), TimeoutSeconds: 30, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

func TestCanonicalJobPayloadIsStable(t *testing.T) {
	payload, err := CanonicalJobPayload(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agentId":"11111111-1111-4111-8111-111111111111","authorizationReference":"test-only:fixture","expiresAt":"2026-08-11T12:05:00Z","issuedAt":"2026-08-11T12:00:00Z","jobId":"33333333-3333-4333-8333-333333333333","moduleId":"mock.safe","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","organizationId":"22222222-2222-4222-8222-222222222222","protocolVersion":"1.0","riskClass":"PASSIVE","scopeEnvironment":"INTERNAL","scopeId":"44444444-4444-4444-8444-444444444444","target":{"type":"HOSTNAME","value":"fixture.test.invalid"},"timeoutSeconds":30,"validatedParameters":{"mode":"synthetic","nested":{"a":null,"b":true},"z":2}}`
	if string(payload) != want {
		t.Fatalf("canonical payload mismatch\n got: %s\nwant: %s", payload, want)
	}
}

func TestEd25519Vector(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	signer := &Ed25519Signer{keyID: "test-only-2026-08", private: private, issuedAt: time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC), fingerprint: hex.EncodeToString(digest[:])}
	signature, err := signer.Sign(context.Background(), testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := CanonicalJobPayload(testEnvelope())
	decoded, _ := base64.StdEncoding.DecodeString(signature)
	if !ed25519.Verify(public, payload, decoded) {
		t.Fatal("generated signature did not verify")
	}
	payloadDigest := sha256.Sum256(payload)
	if got := base64.StdEncoding.EncodeToString(public); got != "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" {
		t.Fatalf("public key vector changed: %s", got)
	}
	if got := signer.Fingerprint(); got != "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9" {
		t.Fatalf("fingerprint vector changed: %s", got)
	}
	if got := hex.EncodeToString(payloadDigest[:]); got != "b459c126b204a51dafa054490519d13fbdb41bcbd123afc38560afe79f6a9348" {
		t.Fatalf("payload digest vector changed: %s", got)
	}
	if signature != "y/7Oi/3cR8qM8lFRmzgj3LsSe7FdM7Rcp2s7ELpM72JTR0RVXuzGqd3DFyyHUBC7UUcTkUcH8Wy+OsN5kfpfCA==" {
		t.Fatalf("signature vector changed: %s", signature)
	}
}
