package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateVerifyTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}
	return id, id.Recipient()
}

func TestVerify_ValidFile(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	id, rec := generateVerifyTestIdentity(t)

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}

	if err := v.Seal(envPath, rec); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	result, err := v.Verify(envPath, id)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.OK {
		t.Errorf("expected OK=true, got message: %s", result.Message)
	}
}

func TestVerify_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	id, _ := generateVerifyTestIdentity(t)

	envPath := filepath.Join(dir, ".env")
	result, err := v.Verify(envPath, id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Error("expected OK=false for missing file")
	}
}

func TestVerify_WrongIdentity(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	_, rec := generateVerifyTestIdentity(t)
	wrongID, _ := generateVerifyTestIdentity(t)

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=abc\n"), 0600); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}
	if err := v.Seal(envPath, rec); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	result, err := v.Verify(envPath, wrongID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Error("expected OK=false with wrong identity")
	}
}

func TestVerifyAll_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	id, rec := generateVerifyTestIdentity(t)

	files := []string{".env", ".env.production", ".env.staging"}
	for _, name := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("K=v\n"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := v.Seal(p, rec); err != nil {
			t.Fatalf("seal %s: %v", name, err)
		}
	}

	results, err := v.VerifyAll(id)
	if err != nil {
		t.Fatalf("VerifyAll error: %v", err)
	}
	if len(results) != len(files) {
		t.Fatalf("expected %d results, got %d", len(files), len(results))
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("expected OK for %s, got: %s", r.Path, r.Message)
		}
	}
}
