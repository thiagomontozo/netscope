package storage

import (
	"bytes"
	"context"
	"testing"
)

func TestLocalStorageRejectsFilenameAndTraversalKeys(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"../../secret.txt", `C:\\Windows\\secret.txt`, "/absolute/secret.txt", "artifacts/../secret.txt"} {
		if err := store.Put(context.Background(), key, bytes.NewReader([]byte("TEST ONLY"))); err == nil {
			t.Fatalf("unsafe storage key %q was accepted", key)
		}
	}
	if err := store.Put(context.Background(), "organizations/org/jobs/job/artifacts/id", bytes.NewReader([]byte("TEST ONLY"))); err != nil {
		t.Fatalf("opaque storage key was rejected: %v", err)
	}
}
