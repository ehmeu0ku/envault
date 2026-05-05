package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateEditTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestEdit_ModifiesVault(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	id := generateEditTestIdentity(t)

	// Write initial .env file and seal it.
	plainPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(plainPath, []byte("KEY=original\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := v.Seal(".env", id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	os.Remove(plainPath)

	// Write a fake editor script that appends a new key.
	editorScript := filepath.Join(dir, "fake-editor.sh")
	script := "#!/bin/sh\necho 'EXTRA=added' >> \"$1\"\n"
	if err := os.WriteFile(editorScript, []byte(script), 0755); err != nil {
		t.Fatalf("write editor script: %v", err)
	}

	if err := v.Edit(".env", id, editorScript); err != nil {
		t.Fatalf("edit: %v", err)
	}

	// Unseal and verify both keys exist.
	if err := v.Unseal(".env", id); err != nil {
		t.Fatalf("unseal after edit: %v", err)
	}
	defer os.Remove(plainPath)

	data, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read plain file: %v", err)
	}
	content := string(data)
	if !contains(content, "KEY=original") {
		t.Errorf("expected KEY=original in output, got: %s", content)
	}
	if !contains(content, "EXTRA=added") {
		t.Errorf("expected EXTRA=added in output, got: %s", content)
	}
}

func TestEdit_MissingVaultFile(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)
	id := generateEditTestIdentity(t)

	err := v.Edit("nonexistent.env", id, "vi")
	if err == nil {
		t.Fatal("expected error for missing vault file")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
