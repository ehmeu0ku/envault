package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateCopyTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestCopy_ReEncryptsToDestination(t *testing.T) {
	srcIdentity := generateCopyTestIdentity(t)
	srcVault := tempVaultWithIdentity(t, srcIdentity)

	envContent := "APP_ENV=production\nSECRET=abc123\n"
	writeEnvFile(t, filepath.Join(srcVault.dir, ".env"), envContent)

	if err := srcVault.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	destDir := t.TempDir()
	destIdentity := generateCopyTestIdentity(t)

	if err := srcVault.Copy(".env", destDir, destIdentity.Recipient()); err != nil {
		t.Fatalf("copy: %v", err)
	}

	// Verify the destination .env.age exists.
	destFile := encryptedPath(filepath.Join(destDir, ".env"))
	if _, err := os.Stat(destFile); os.IsNotExist(err) {
		t.Fatalf("expected dest file %s to exist", destFile)
	}

	// Decrypt with dest identity and verify contents.
	destVault := tempVaultWithIdentity(t, destIdentity)
	destVault.dir = destDir

	if err := destVault.Unseal(".env.age"); err != nil {
		t.Fatalf("unseal at destination: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, ".env"))
	if err != nil {
		t.Fatalf("read unsealed file: %v", err)
	}
	if string(got) != envContent {
		t.Errorf("content mismatch: got %q, want %q", got, envContent)
	}
}

func TestCopy_MissingSourceFile(t *testing.T) {
	srcIdentity := generateCopyTestIdentity(t)
	srcVault := tempVaultWithIdentity(t, srcIdentity)

	destDir := t.TempDir()
	destIdentity := generateCopyTestIdentity(t)

	err := srcVault.Copy(".env", destDir, destIdentity.Recipient())
	if err == nil {
		t.Fatal("expected error for missing source file, got nil")
	}
}

func TestCopy_CreatesDestDirIfMissing(t *testing.T) {
	srcIdentity := generateCopyTestIdentity(t)
	srcVault := tempVaultWithIdentity(t, srcIdentity)

	envContent := "KEY=value\n"
	writeEnvFile(t, filepath.Join(srcVault.dir, ".env"), envContent)

	if err := srcVault.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	destDir := filepath.Join(t.TempDir(), "nested", "dir")
	destIdentity := generateCopyTestIdentity(t)

	if err := srcVault.Copy(".env", destDir, destIdentity.Recipient()); err != nil {
		t.Fatalf("copy: %v", err)
	}

	destFile := encryptedPath(filepath.Join(destDir, ".env"))
	if _, err := os.Stat(destFile); os.IsNotExist(err) {
		t.Fatalf("expected dest file to exist at %s", destFile)
	}
}
