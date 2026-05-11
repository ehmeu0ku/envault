package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateCloneTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestClone_CopiesEncryptedContent(t *testing.T) {
	srcIdentity := generateCloneTestIdentity(t)
	dstIdentity := generateCloneTestIdentity(t)

	dir := t.TempDir()
	plainPath := filepath.Join(dir, ".env")
	srcSealed := filepath.Join(dir, ".env.age")
	dstSealed := filepath.Join(dir, "dest", ".env.age")

	if err := os.WriteFile(plainPath, []byte("CLONE_KEY=hello\nOTHER=world\n"), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	if err := EncryptFile(plainPath, srcSealed, []age.Recipient{srcIdentity.Recipient()}); err != nil {
		t.Fatalf("encrypt source: %v", err)
	}

	if err := Clone(srcSealed, srcIdentity, dstSealed, []age.Recipient{dstIdentity.Recipient()}); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// Decrypt with destination identity and verify content
	outPath := filepath.Join(dir, "out.env")
	if err := DecryptFile(dstSealed, outPath, dstIdentity); err != nil {
		t.Fatalf("decrypt destination: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "CLONE_KEY=hello\nOTHER=world\n" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestClone_MissingSourceFile(t *testing.T) {
	id := generateCloneTestIdentity(t)
	dir := t.TempDir()

	err := Clone(filepath.Join(dir, "nonexistent.age"), id, filepath.Join(dir, "dst.age"), []age.Recipient{id.Recipient()})
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

func TestClone_NoRecipients(t *testing.T) {
	id := generateCloneTestIdentity(t)
	dir := t.TempDir()
	plainPath := filepath.Join(dir, ".env")
	srcSealed := filepath.Join(dir, ".env.age")

	if err := os.WriteFile(plainPath, []byte("KEY=val\n"), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := EncryptFile(plainPath, srcSealed, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	err := Clone(srcSealed, id, filepath.Join(dir, "dst.age"), nil)
	if err == nil {
		t.Fatal("expected error for empty recipients, got nil")
	}
}

func TestClone_CreatesDestinationDirectory(t *testing.T) {
	id := generateCloneTestIdentity(t)
	dir := t.TempDir()
	plainPath := filepath.Join(dir, ".env")
	srcSealed := filepath.Join(dir, ".env.age")
	dstSealed := filepath.Join(dir, "a", "b", "c", ".env.age")

	if err := os.WriteFile(plainPath, []byte("X=1\n"), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := EncryptFile(plainPath, srcSealed, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if err := Clone(srcSealed, id, dstSealed, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	if _, err := os.Stat(dstSealed); os.IsNotExist(err) {
		t.Error("destination file was not created")
	}
}
