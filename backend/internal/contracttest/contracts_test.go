package contracttest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestPublishedSchemasAndFixturesAreValidJSON(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "agent", "v1")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
		}
		if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s is not draft 2020-12", entry.Name())
		}
	}
	fixtures := filepath.Join(root, "fixtures")
	fixtureEntries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	validCount, invalidCount := 0, 0
	for _, entry := range fixtureEntries {
		data, err := os.ReadFile(filepath.Join(fixtures, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Errorf("%s is invalid JSON: %v", entry.Name(), err)
		}
		if strings.Contains(entry.Name(), ".valid.") {
			validCount++
		}
		if strings.Contains(entry.Name(), ".invalid-") {
			invalidCount++
		}
	}
	if validCount < 11 || invalidCount < 2 {
		t.Fatalf("fixture coverage too small: valid=%d invalid=%d", validCount, invalidCount)
	}
}

func TestFixturesValidateAgainstDraft202012Schemas(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "agent", "v1")
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.AssertContent()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if json.Unmarshal(data, &document) != nil {
			t.Fatalf("schema %s is invalid JSON", entry.Name())
		}
		if err := compiler.AddResource(entry.Name(), document); err != nil {
			t.Fatal(err)
		}
		if object, ok := document.(map[string]any); ok {
			if id, ok := object["$id"].(string); ok {
				if err := compiler.AddResource(id, document); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	schemas := map[string]*jsonschema.Schema{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		schemas[entry.Name()] = compiler.MustCompile(entry.Name())
	}
	mapping := map[string]string{"enrollment-request": "enrollment.schema.json", "enrollment-response": "enrollment.schema.json", "heartbeat": "heartbeat.schema.json", "capabilities": "capabilities.schema.json", "job-envelope": "job-envelope.schema.json", "job-result": "job-result.schema.json", "job-failure": "job-failure.schema.json", "job-cancellation": "job-cancellation.schema.json", "evidence-manifest": "evidence-manifest.schema.json", "artifact-manifest": "artifact-manifest.schema.json", "protocol-error": "errors.schema.json"}
	fixtureEntries, err := os.ReadDir(filepath.Join(root, "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range fixtureEntries {
		base := strings.Split(entry.Name(), ".")[0]
		schemaName, ok := mapping[base]
		if !ok {
			t.Fatalf("fixture %s has no schema mapping", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(root, "fixtures", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var instance any
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.UseNumber()
		if decoder.Decode(&instance) != nil {
			t.Fatalf("fixture %s invalid JSON", entry.Name())
		}
		validationErr := schemas[schemaName].Validate(instance)
		valid := strings.Contains(entry.Name(), ".valid.")
		if valid && validationErr != nil {
			t.Errorf("valid fixture %s rejected: %v", entry.Name(), validationErr)
		}
		if !valid && validationErr == nil {
			t.Errorf("invalid fixture %s accepted", entry.Name())
		}
	}
}

func TestContractSecurityFieldsRemainPublished(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "agent", "v1")
	checks := map[string][]string{"job-envelope.schema.json": {"signingKeyId", "signatureAlgorithm", "signature", "nonce", "expiresAt"}, "artifact-manifest.schema.json": {"direction", "sizeBytes", "sha256", "status"}, "enrollment.schema.json": {"jobSigningKeyId", "jobSigningPublicKey", "jobSigningKeyFingerprint"}}
	for file, fields := range checks {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range fields {
			if !strings.Contains(string(data), `"`+field+`"`) {
				t.Errorf("%s omitted %s", file, field)
			}
		}
	}
}
