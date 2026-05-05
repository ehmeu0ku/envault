package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/yourorg/envault/internal/crypto"
)

func generateTestIdentity(t *testing.T) (*age.X25519Identity, string, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	return identity, identity.String(), identity.Recipient().String()
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	_, identityKey, recipientKey := generateTestIdentity(t)

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, ".env")
	encPath := filepath.Join(tmpDir, ".env.age")
	dstPath := filepath.Join(tmpDir, ".env.decrypted")

	original := []byte("DB_HOST=localhost\nDB_PASS=supersecret\nAPI_KEY=abc123\n")
	if err := os.WriteFile(srcPath, original, 0600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := crypto.EncryptFile(srcPath, encPath, recipientKey); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	encContent, _ := os.ReadFile(encPath)
	if len(encContent) == 0 {
		t.Fatal("encrypted file is empty")
	}
	if string(encContent) == string(original) {
		t.Fatal("encrypted file must differ from plaintext")
	}

	if err := crypto.DecryptFile(encPath, dstPath, identityKey); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	decrypted, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("reading decrypted file: %v", err)
	}
	if string(decrypted) != string(original) {
		t.Errorf("roundtrip mismatch\ngot:  %q\nwant: %q", decrypted, original)
	}
}

func TestEncryptFile_InvalidRecipient(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, ".env")
	_ = os.WriteFile(src, []byte("KEY=val"), 0600)

	err := crypto.EncryptFile(src, filepath.Join(tmpDir, "out.age"), "not-a-valid-key")
	if err == nil {
		t.Fatal("expected error for invalid recipient key")
	}
}

func TestDecryptFile_InvalidIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	_, identityKey, recipientKey := generateTestIdentity(t)

	src := filepath.Join(tmpDir, ".env")
	enc := filepath.Join(tmpDir, ".env.age")
	_ = os.WriteFile(src, []byte("KEY=val"), 0600)
	_ = crypto.EncryptFile(src, enc, recipientKey)

	// Use a different identity — should fail
	_, wrongIdentity, _ := generateTestIdentity(t)
	_ = identityKey

	err := crypto.DecryptFile(enc, filepath.Join(tmpDir, "out"), wrongIdentity)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong identity")
	}
}
