package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/nicholasgasior/envault/internal/vault"
)

func generateRenameTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestRename_MovesEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id := generateRenameTestIdentity(t)
	v := vault.New(dir, id)

	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := v.Seal(envFile); err != nil {
		t.Fatalf("seal: %v", err)
	}

	if err := v.Rename(".env", ".env.production"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	oldEnc := filepath.Join(dir, ".env.age")
	newEnc := filepath.Join(dir, ".env.production.age")

	if _, err := os.Stat(oldEnc); !os.IsNotExist(err) {
		t.Errorf("expected old encrypted file to be gone, but it still exists")
	}

	if _, err := os.Stat(newEnc); err != nil {
		t.Errorf("expected new encrypted file to exist: %v", err)
	}
}

func TestRename_MissingSourceFile(t *testing.T) {
	dir := t.TempDir()
	id := generateRenameTestIdentity(t)
	v := vault.New(dir, id)

	err := v.Rename(".env.missing", ".env.new")
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

func TestRename_DestinationAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	id := generateRenameTestIdentity(t)
	v := vault.New(dir, id)

	for _, name := range []string{".env", ".env.staging"} {
		envFile := filepath.Join(dir, name)
		if err := os.WriteFile(envFile, []byte("K=v\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := v.Seal(envFile); err != nil {
			t.Fatalf("seal %s: %v", name, err)
		}
	}

	err := v.Rename(".env", ".env.staging")
	if err == nil {
		t.Fatal("expected error when destination exists, got nil")
	}
}
