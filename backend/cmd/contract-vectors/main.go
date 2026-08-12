// Command contract-vectors regenerates TEST ONLY RFC 8785/Ed25519 vectors.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thiagomontozo/netscope/backend/internal/canonicaljson"
)

const (
	testSeed         = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	testSigningKeyID = "test-only-2026-08"
)

type vector struct {
	Name                 string          `json:"name"`
	Input                json.RawMessage `json:"input"`
	Canonical            string          `json:"canonical"`
	SHA256               string          `json:"sha256"`
	SignatureAlgorithm   string          `json:"signatureAlgorithm"`
	SigningKeyID         string          `json:"signingKeyId"`
	TestPublicKey        string          `json:"testPublicKey"`
	Signature            string          `json:"signature"`
	ExpectedVerification string          `json:"expectedVerification"`
}

func main() {
	seed, _ := hex.DecodeString(testSeed)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	inputs := []struct{ name, raw string }{
		{"integer", `{"value":443}`},
		{"decimal", `{"packetLossThreshold":2.5,"latencyMultiplier":1.25}`},
		{"negative-number", `{"negativeExample":-3.75}`},
		{"zero", `{"integer":0,"decimal":0.0,"negative":-0}`},
		{"nested-object", `{"z":{"second":2,"first":1},"a":{"nested":true}}`},
		{"arrays", `{"values":[3,2.5,-3.75,0,{"b":2,"a":1}]}`},
		{"unicode", `{"€":"Euro","\r":"CR","😀":"Emoji","ö":"Diaeresis"}`},
		{"parameters-mixed", `{"port":443,"timeoutSeconds":30,"packetLossThreshold":2.5,"latencyMultiplier":1.25,"negativeExample":-3.75,"enabled":true,"mode":"synthetic"}`},
		{"job-envelope-basic", jobPayload(`{"mode":"synthetic","port":443}`)},
		{"job-envelope-decimal-parameters", jobPayload(`{"latencyMultiplier":1.25,"packetLossThreshold":2.5}`)},
		{"job-envelope-nested-parameters", jobPayload(`{"profile":{"thresholds":[1.25,2.5],"enabled":true},"ports":[443,8443]}`)},
	}
	root := filepath.Join("..", "contracts", "agent", "v1", "test-vectors")
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	for _, input := range inputs {
		canonical, err := canonicaljson.Canonicalize([]byte(input.raw))
		if err != nil {
			panic(fmt.Errorf("%s: %w", input.name, err))
		}
		digest := sha256.Sum256(canonical)
		encoded, err := json.MarshalIndent(vector{Name: input.name, Input: json.RawMessage(input.raw), Canonical: string(canonical), SHA256: hex.EncodeToString(digest[:]), SignatureAlgorithm: "Ed25519", SigningKeyID: testSigningKeyID, TestPublicKey: base64.StdEncoding.EncodeToString(public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)), ExpectedVerification: "VALID"}, "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(root, input.name+".json"), append(encoded, '\n'), 0o644); err != nil {
			panic(err)
		}
	}
}

func jobPayload(parameters string) string {
	return `{"agentId":"11111111-1111-4111-8111-111111111111","authorizationReference":"test-only:fixture","expiresAt":"2026-08-11T12:05:00Z","issuedAt":"2026-08-11T12:00:00Z","jobId":"33333333-3333-4333-8333-333333333333","moduleId":"mock.safe","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","organizationId":"22222222-2222-4222-8222-222222222222","protocolVersion":"1.0","riskClass":"PASSIVE","scopeEnvironment":"INTERNAL","scopeId":"44444444-4444-4444-8444-444444444444","target":{"type":"HOSTNAME","value":"fixture.test.invalid"},"timeoutSeconds":30,"validatedParameters":` + parameters + `}`
}
