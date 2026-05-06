package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateRestoreTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestRestoreSnapshot_RestoresFile(t *testing.T) {
	dir := t.TempDir()
	id := generateRestoreTestIdentity(t)
	v := New(dir, ".env")

	// Write and seal a plain env file.
	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("KEY=original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Take a snapshot.
	snapID, err := v.TakeSnapshot(id.Recipient())
	if err != nil {
		t.Fatalf("take snapshot: %v", err)
	}

	// Overwrite the vault with different content.
	if err := os.WriteFile(plain, []byte("KEY=modified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(id.Recipient()); err != nil {
		t.Fatalf("reseal: %v", err)
	}

	// Restore from snapshot.
	if err := v.RestoreSnapshot(snapID, id); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Unseal and verify original content is back.
	if err := v.Unseal(id); err != nil {
		t.Fatalf("unseal after restore: %v", err)
	}
	got, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "KEY=original\n" {
		t.Errorf("expected original content, got %q", got)
	}
}

func TestRestoreSnapshot_MissingSnapshot(t *testing.T) {
	dir := t.TempDir()
	id := generateRestoreTestIdentity(t)
	v := New(dir, ".env")

	err := v.RestoreSnapshot("nonexistent-id", id)
	if err == nil {
		t.Fatal("expected error for missing snapshot")
	}
}

func TestRestoreSnapshot_CreatesBackup(t *testing.T) {
	dir := t.TempDir()
	id := generateRestoreTestIdentity(t)
	v := New(dir, ".env")

	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("KEY=v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	snapID, err := v.TakeSnapshot(id.Recipient())
	if err != nil {
		t.Fatalf("take snapshot: %v", err)
	}

	if err := v.RestoreSnapshot(snapID, id); err != nil {
		t.Fatalf("restore: %v", err)
	}

	bakPath := encryptedPath(dir, ".env") + ".bak"
	if _, err := os.Stat(bakPath); os.IsNotExist(err) {
		t.Error("expected backup file to exist")
	}
}
