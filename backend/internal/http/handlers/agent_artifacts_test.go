package handlers

import "testing"

func TestArtifactContentTypePolicyDoesNotTrustExtension(t *testing.T) {
	for _, allowed := range []string{"application/octet-stream", "application/json", "text/plain", "application/vnd.tcpdump.pcap"} {
		if !allowedArtifactContentType(allowed) {
			t.Fatalf("allowed content type %q was rejected", allowed)
		}
	}
	for _, rejected := range []string{"text/html", "application/x-msdownload", "text/plain; name=artifact.txt", "application/json\r\nX-Test: injected", ""} {
		if allowedArtifactContentType(rejected) {
			t.Fatalf("unauthorized content type %q was accepted", rejected)
		}
	}
}

func TestArtifactStorageKeyIgnoresOriginalFilename(t *testing.T) {
	want := "organizations/org/jobs/job/artifacts/artifact"
	if got := artifactStorageKey("org", "job", "artifact"); got != want {
		t.Fatalf("storage key mismatch: %s", got)
	}
	// There is deliberately no filename argument, so ../../secret.txt and
	// Windows reserved names cannot influence the physical key.
}
