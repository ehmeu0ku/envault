package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func tempPinDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-pin-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLoadPins_EmptyOnMissing(t *testing.T) {
	dir := tempPinDir(t)
	entries, err := LoadPins(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty pins, got %d", len(entries))
	}
}

func TestAddPin_CreatesEntry(t *testing.T) {
	dir := tempPinDir(t)
	encPath := filepath.Join(dir, "secrets.env.age")

	if err := AddPin(dir, encPath, "prod secrets"); err != nil {
		t.Fatalf("AddPin failed: %v", err)
	}

	entries, err := LoadPins(dir)
	if err != nil {
		t.Fatalf("LoadPins failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Path != encPath {
		t.Errorf("expected path %q, got %q", encPath, entries[0].Path)
	}
	if entries[0].Label != "prod secrets" {
		t.Errorf("expected label 'prod secrets', got %q", entries[0].Label)
	}
}

func TestAddPin_UpdatesExisting(t *testing.T) {
	dir := tempPinDir(t)
	encPath := filepath.Join(dir, "secrets.env.age")

	_ = AddPin(dir, encPath, "old label")
	_ = AddPin(dir, encPath, "new label")

	entries, err := LoadPins(dir)
	if err != nil {
		t.Fatalf("LoadPins failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after update, got %d", len(entries))
	}
	if entries[0].Label != "new label" {
		t.Errorf("expected 'new label', got %q", entries[0].Label)
	}
}

func TestRemovePin_DeletesEntry(t *testing.T) {
	dir := tempPinDir(t)
	path1 := filepath.Join(dir, "a.env.age")
	path2 := filepath.Join(dir, "b.env.age")

	_ = AddPin(dir, path1, "")
	_ = AddPin(dir, path2, "")
	_ = RemovePin(dir, path1)

	entries, err := LoadPins(dir)
	if err != nil {
		t.Fatalf("LoadPins failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after remove, got %d", len(entries))
	}
	if entries[0].Path != path2 {
		t.Errorf("expected remaining path %q, got %q", path2, entries[0].Path)
	}
}

func TestIsPinned_TrueAndFalse(t *testing.T) {
	dir := tempPinDir(t)
	encPath := filepath.Join(dir, "secrets.env.age")

	pinned, err := IsPinned(dir, encPath)
	if err != nil {
		t.Fatalf("IsPinned failed: %v", err)
	}
	if pinned {
		t.Error("expected not pinned before AddPin")
	}

	_ = AddPin(dir, encPath, "")

	pinned, err = IsPinned(dir, encPath)
	if err != nil {
		t.Fatalf("IsPinned failed: %v", err)
	}
	if !pinned {
		t.Error("expected pinned after AddPin")
	}
}
