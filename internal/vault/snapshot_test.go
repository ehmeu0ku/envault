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
	v := New(dir, id)

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	snap, err := v.TakeSnapshot(".env")
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	if snap.Name == "" {
		t.Error("expected non-empty snapshot name")
	}

	snapshotFile := filepath.Join(snapshotDir(dir), snap.Name)
	if _, err := os.Stat(snapshotFile); err != nil {
		t.Errorf("snapshot file not found: %v", err)
	}
}

func TestListSnapshots_Empty(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, id)

	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(snaps))
	}
}

func TestListSnapshots_AfterMultipleTakes(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, id)

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := v.TakeSnapshot(".env"); err != nil {
			t.Fatalf("TakeSnapshot %d: %v", i, err)
		}
	}

	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(snaps))
	}
}

func TestTakeSnapshot_MissingSource(t *testing.T) {
	dir := t.TempDir()
	id := generateSnapshotTestIdentity(t)
	v := New(dir, id)

	_, err := v.TakeSnapshot("nonexistent.env")
	if err == nil {
		t.Error("expected error for missing source file")
	}
}
