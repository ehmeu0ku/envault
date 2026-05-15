package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/nicholasgasior/envault/internal/crypto"
	"github.com/nicholasgasior/envault/internal/vault"
)

func generateArchiveTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestArchiveExtract_RealEncryptedFiles(t *testing.T) {
	id := generateArchiveTestIdentity(t)
	vaultDir := t.TempDir()
	archiveDir := t.TempDir()
	extractDir := t.TempDir()

	// Seal two env files into the vault dir
	envFiles := map[string]string{
		"prod.env":    "DB_HOST=prod.db\nSECRET=abc123\n",
		"staging.env": "DB_HOST=staging.db\nSECRET=xyz789\n",
	}
	for name, content := range envFiles {
		plainPath := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(plainPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		encPath := filepath.Join(vaultDir, name+".age")
		if err := crypto.EncryptFile(plainPath, encPath, []age.Recipient{id.Recipient()}); err != nil {
			t.Fatalf("encrypt %s: %v", name, err)
		}
	}

	// Archive the vault
	destZip := filepath.Join(archiveDir, "vault.zip")
	n, err := vault.Archive(vaultDir, destZip)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 archived, got %d", n)
	}

	// Extract into a fresh directory
	result, err := vault.Extract(destZip, extractDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result.Extracted != 2 {
		t.Fatalf("expected 2 extracted, got %d", result.Extracted)
	}

	// Verify each extracted file is still decryptable
	for name, wantContent := range envFiles {
		encPath := filepath.Join(extractDir, name+".age")
		outPath := filepath.Join(t.TempDir(), name+".out")
		if err := crypto.DecryptFile(encPath, outPath, []*age.X25519Identity{id}); err != nil {
			t.Fatalf("decrypt %s after extract: %v", name, err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != wantContent {
			t.Errorf("%s: content mismatch\ngot:  %q\nwant: %q", name, got, wantContent)
		}
	}
}
