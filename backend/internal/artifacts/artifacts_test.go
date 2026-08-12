package artifacts

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestTransferTokenIsScopedAndExpires(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := TokenManager{Key: []byte("TEST ONLY 32-byte artifact token key material"), TTL: time.Minute, Now: func() time.Time { return now }}
	claims := TransferClaims{ArtifactID: "artifact-1", OrganizationID: "org-1", AgentID: "agent-1", JobID: "job-1", Purpose: PurposeDownload}
	token, err := manager.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(token, claims); err != nil {
		t.Fatal(err)
	}
	wrong := claims
	wrong.AgentID = "agent-2"
	if _, err := manager.Verify(token, wrong); err == nil {
		t.Fatal("cross-agent token was accepted")
	}
	manager.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := manager.Verify(token, claims); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestCopyVerifiedStreamsAndRejectsMismatch(t *testing.T) {
	content := []byte("TEST ONLY synthetic artifact\n")
	var output bytes.Buffer
	_, err := CopyVerified(context.Background(), &output, bytes.NewReader(content), int64(len(content)), 1024, "5154c4cb28216a86aea7175641f5270dc02fd1876652d29d56a62cff9dde1173")
	if err != nil || !bytes.Equal(output.Bytes(), content) {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	output.Reset()
	_, err = CopyVerified(context.Background(), &output, bytes.NewReader(content), int64(len(content)), 1024, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}
