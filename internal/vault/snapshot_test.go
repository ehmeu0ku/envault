package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateSnapshotTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestTakeSnapshot_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, ".env")

	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	snapID, err := v.TakeSnapshot(id.Recipient())
	if err != nil {
		t.Fatalf("take snapshot: %v", err)
	}

	snapPath := filepath.Join(snapshotDir(dir), snapID+".age")
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		t.Errorf("snapshot file not created at %s", snapPath)
	}
}

func TestListSnapshots_Empty(t *testing.T) {
	dir := t.TempDir()
	v := New(dir, ".env")

	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(snaps))
	}
}

func TestListSnapshots_AfterMultipleTakes(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, ".env")

	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := v.TakeSnapshot(id.Recipient()); err != nil {
			t.Fatalf("take snapshot %d: %v", i, err)
		}
	}

	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(snaps) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(snaps))
	}
}

func TestTakeSnapshot_MissingSource(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, ".env")

	_, err := v.TakeSnapshot(id.Recipient())
	if err == nil {
		t.Fatal("expected error for missing sealed vault")
	}
}
