package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/envault/internal/keystore"
	"github.com/user/envault/internal/vault"
)

func tempVault(t *testing.T) (*vault.Vault, string) {
	t.Helper()
	dir := t.TempDir()
	ksPath := filepath.Join(dir, "key.txt")

	ks := keystore.New(ksPath)
	if err := ks.Generate(); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return vault.New(ks), dir
}

func writeEnvFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return p
}

func TestSealUnseal_Roundtrip(t *testing.T) {
	v, dir := tempVault(t)
	origContent := "SECRET=hunter2\nAPI_KEY=abc123\n"
	envPath := writeEnvFile(t, dir, ".env", origContent)

	agePath, err := v.Seal(envPath)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Remove plaintext before unsealing to prove round-trip.
	if err := os.Remove(envPath); err != nil {
		t.Fatalf("remove plaintext: %v", err)
	}

	outPath, err := v.Unseal(agePath)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(got) != origContent {
		t.Errorf("content mismatch: got %q, want %q", got, origContent)
	}
}

func TestSeal_MissingFile(t *testing.T) {
	v, dir := tempVault(t)
	_, err := v.Seal(filepath.Join(dir, "nonexistent.env"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestUnseal_WrongSuffix(t *testing.T) {
	v, dir := tempVault(t)
	_, err := v.Unseal(filepath.Join(dir, ".env"))
	if err == nil {
		t.Fatal("expected error for wrong suffix, got nil")
	}
}

func TestSeal_ProducesAgeFile(t *testing.T) {
	v, dir := tempVault(t)
	envPath := writeEnvFile(t, dir, ".env", "FOO=bar\n")

	agePath, err := v.Seal(envPath)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := os.Stat(agePath); err != nil {
		t.Errorf("encrypted file not created: %v", err)
	}
}
