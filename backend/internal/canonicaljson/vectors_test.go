package canonicaljson

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testVector struct {
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

func TestPublishedCanonicalizationAndCryptoVectors(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "contracts", "agent", "v1", "test-vectors", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var vector testVector
		if json.Unmarshal(encoded, &vector) != nil || vector.Input == nil {
			continue // Legacy non-JCS vectors are validated by their owning packages.
		}
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := Canonicalize(vector.Input)
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != vector.Canonical {
				t.Fatalf("canonical mismatch: %s", canonical)
			}
			digest := sha256.Sum256(canonical)
			if hex.EncodeToString(digest[:]) != vector.SHA256 {
				t.Fatal("SHA-256 mismatch")
			}
			public, publicErr := base64.StdEncoding.DecodeString(vector.TestPublicKey)
			signature, signatureErr := base64.StdEncoding.DecodeString(vector.Signature)
			if publicErr != nil || signatureErr != nil || vector.SignatureAlgorithm != "Ed25519" || vector.SigningKeyID == "" || vector.ExpectedVerification != "VALID" || !ed25519.Verify(public, canonical, signature) {
				t.Fatal("Ed25519 vector did not verify")
			}
		})
		verified++
	}
	if verified != 11 {
		t.Fatalf("verified %d JCS vectors; expected 11", verified)
	}
}
