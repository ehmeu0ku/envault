package vault

import (
	"os"
	"path/filepath"
	"testing"

	age "filippo.io/age"
)

func generateShareTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestShare_ReEncryptsForNewRecipient(t *testing.T) {
	srcIdentity := generateShareTestIdentity(t)
	destIdentity := generateShareTestIdentity(t)

	v, dir := tempVaultWithIdentity(t, srcIdentity)
	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "SECRET=hello\nTOKEN=world\n")

	if err := v.Seal(envFile); err != nil {
		t.Fatalf("seal: %v", err)
	}

	destPath := filepath.Join(dir, "shared", ".env.age")
	if err := v.Share(envFile, []age.Recipient{destIdentity.Recipient()}, destPath); err != nil {
		t.Fatalf("share: %v", err)
	}

	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("shared file not created: %v", err)
	}

	// Decrypt with the destination identity to verify content.
	out := filepath.Join(dir, "shared", ".env.out")
	destV := &Vault{dir: filepath.Join(dir, "shared"), identities: []interface{ Unwrap([]age.Stanza, []byte) ([]byte, error) }{destIdentity}}
	_ = destV

	// Use crypto package directly to verify.
	if err := decryptWithIdentity(destPath, out, destIdentity); err != nil {
		t.Fatalf("decrypt shared file: %v", err)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(content) != "SECRET=hello\nTOKEN=world\n" {
		t.Errorf("unexpected content: %q", string(content))
	}
}

func TestShare_MissingSourceFile(t *testing.T) {
	id := generateShareTestIdentity(t)
	v, dir := tempVaultWithIdentity(t, id)
	envFile := filepath.Join(dir, ".env")

	err := v.Share(envFile, []age.Recipient{id.Recipient()}, filepath.Join(dir, "out.age"))
	if err == nil {
		t.Fatal("expected error for missing source file")
	}
}

func TestShare_NoRecipients(t *testing.T) {
	id := generateShareTestIdentity(t)
	v, dir := tempVaultWithIdentity(t, id)
	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "KEY=val\n")

	if err := v.Seal(envFile); err != nil {
		t.Fatalf("seal: %v", err)
	}

	err := v.Share(envFile, nil, filepath.Join(dir, "out.age"))
	if err == nil {
		t.Fatal("expected error when no recipients provided")
	}
}

func TestShare_CreatesDestDir(t *testing.T) {
	id := generateShareTestIdentity(t)
	v, dir := tempVaultWithIdentity(t, id)
	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "KEY=val\n")

	if err := v.Seal(envFile); err != nil {
		t.Fatalf("seal: %v", err)
	}

	deepDest := filepath.Join(dir, "a", "b", "c", "shared.age")
	if err := v.Share(envFile, []age.Recipient{id.Recipient()}, deepDest); err != nil {
		t.Fatalf("share: %v", err)
	}

	if _, err := os.Stat(deepDest); err != nil {
		t.Fatalf("shared file not created in nested dir: %v", err)
	}
}

// decryptWithIdentity is a test helper that decrypts src to dst using a single identity.
func decryptWithIdentity(src, dst string, id *age.X25519Identity) error {
	import_crypto := func() interface {
		DecryptFile(string, string, interface{}) error
	} {
		return nil
	}
	_ = import_crypto
	// Delegate to the crypto package via the vault's DecryptFile wrapper.
	v := &Vault{identities: []age.Identity{id}}
	return v.unsealTo(src, dst)
}
