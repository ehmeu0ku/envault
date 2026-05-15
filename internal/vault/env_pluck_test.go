package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/yourusername/envault/internal/crypto"
)

func generatePluckTestIdentity(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(keyPath, []byte(id.String()), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return id, keyPath
}

func sealPluckEnv(t *testing.T, dir, filename, content string, id *age.X25519Identity) {
	t.Helper()
	plainPath := filepath.Join(dir, filename)
	if err := os.WriteFile(plainPath, []byte(content), 0644); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	encPath := plainPath + ".age"
	if err := crypto.EncryptFile(plainPath, encPath, id.Recipient().String()); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
}

func TestPluck_ExtractsRequestedKeys(t *testing.T) {
	id, keyPath := generatePluckTestIdentity(t)
	dir := t.TempDir()
	sealPluckEnv(t, dir, ".env", "FOO=bar\nBAZ=qux\nSECRET=hidden\n", id)

	result, err := Pluck(filepath.Join(dir, ".env"), PluckOptions{
		Identity: keyPath,
		Keys:     []string{"FOO", "BAZ"},
	})
	if err != nil {
		t.Fatalf("Pluck: %v", err)
	}
	if result.Pairs["FOO"] != "bar" {
		t.Errorf("FOO = %q, want %q", result.Pairs["FOO"], "bar")
	}
	if result.Pairs["BAZ"] != "qux" {
		t.Errorf("BAZ = %q, want %q", result.Pairs["BAZ"], "qux")
	}
	if _, ok := result.Pairs["SECRET"]; ok {
		t.Error("SECRET should not be included")
	}
}

func TestPluck_ReportsMissingKeys(t *testing.T) {
	id, keyPath := generatePluckTestIdentity(t)
	dir := t.TempDir()
	sealPluckEnv(t, dir, ".env", "PRESENT=yes\n", id)

	result, err := Pluck(filepath.Join(dir, ".env"), PluckOptions{
		Identity: keyPath,
		Keys:     []string{"PRESENT", "ABSENT"},
	})
	if err != nil {
		t.Fatalf("Pluck: %v", err)
	}
	if len(result.Missing) != 1 || result.Missing[0] != "ABSENT" {
		t.Errorf("Missing = %v, want [ABSENT]", result.Missing)
	}
}

func TestPluck_MissingEncryptedFile(t *testing.T) {
	_, keyPath := generatePluckTestIdentity(t)
	dir := t.TempDir()

	_, err := Pluck(filepath.Join(dir, ".env"), PluckOptions{
		Identity: keyPath,
		Keys:     []string{"FOO"},
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestPluck_NoKeysReturnsError(t *testing.T) {
	id, keyPath := generatePluckTestIdentity(t)
	dir := t.TempDir()
	sealPluckEnv(t, dir, ".env", "FOO=bar\n", id)

	_, err := Pluck(filepath.Join(dir, ".env"), PluckOptions{
		Identity: keyPath,
		Keys:     []string{},
	})
	if err == nil {
		t.Fatal("expected error when no keys specified")
	}
}
