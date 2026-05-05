package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestRotate_ReEncryptsFile(t *testing.T) {
	v, dir := tempVault(t)
	writeEnvFile(t, dir, "app.env", "SECRET=original")

	if err := v.Seal("app.env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	newIdentity := generateTestIdentity(t)
	if err := v.Rotate("app.env", newIdentity.Recipient()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Unseal with new identity
	v2, _ := tempVaultWithIdentity(t, dir, newIdentity)
	outPath := filepath.Join(dir, "app.env.out")
	if err := v2.UnsealTo("app.env", outPath); err != nil {
		t.Fatalf("unseal with new identity: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "SECRET=original" {
		t.Errorf("expected original content, got %q", string(data))
	}
}

func TestRotate_MissingFile(t *testing.T) {
	v, _ := tempVault(t)
	newIdentity := generateTestIdentity(t)
	err := v.Rotate("nonexistent.env", newIdentity.Recipient())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRotateAll_RotatesMultipleFiles(t *testing.T) {
	v, dir := tempVault(t)
	for _, name := range []string{"a.env", "b.env", "c.env"} {
		writeEnvFile(t, dir, name, "KEY=value")
		if err := v.Seal(name); err != nil {
			t.Fatalf("seal %s: %v", name, err)
		}
	}

	newIdentity := generateTestIdentity(t)
	rotated, err := v.RotateAll(newIdentity.Recipient())
	if err != nil {
		t.Fatalf("rotate-all: %v", err)
	}
	if len(rotated) != 3 {
		t.Errorf("expected 3 rotated, got %d", len(rotated))
	}
}

// tempVaultWithIdentity creates a vault in an existing dir with a specific identity.
func tempVaultWithIdentity(t *testing.T, dir string, id *age.X25519Identity) (*Vault, string) {
	t.Helper()
	v := New(dir, id)
	return v, dir
}
