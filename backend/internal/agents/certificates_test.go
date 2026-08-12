package agents

import (
	"testing"
	"time"
)

func TestCertificatePolicyDetectsRotationWindowWithoutLooping(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	policy := DefaultCertificatePolicy()
	if !policy.NeedsRotation(now.Add(14*24*time.Hour), now) {
		t.Fatal("certificate at rotation boundary was not detected")
	}
	if policy.NeedsRotation(now.Add(15*24*time.Hour), now) {
		t.Fatal("certificate outside rotation boundary was detected")
	}
	newCertificateExpiry := now.Add(policy.Lifetime)
	if policy.NeedsRotation(newCertificateExpiry, now) {
		t.Fatal("new certificate would immediately rotate again")
	}
}
