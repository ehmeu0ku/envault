package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestList_Empty(t *testing.T) {
	v, dir := tempVault(t)
	entries, err := v.List(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestList_FindsAgeFiles(t *testing.T) {
	v, dir := tempVault(t)

	// Create fake sealed files.
	for _, name := range []string{".env.age", ".env.production.age"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// A non-.age file should be ignored.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := v.List(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Name == "" {
			t.Error("entry Name should not be empty")
		}
		if e.PlainPath == e.Path {
			t.Error("PlainPath and Path should differ")
		}
	}
}

func TestEntry_Status(t *testing.T) {
	v, dir := tempVault(t)

	agePath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(agePath, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := v.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if got := e.Status(); got != "sealed" {
		t.Errorf("expected sealed, got %s", got)
	}

	// Write the plain counterpart.
	if err := os.WriteFile(e.PlainPath, []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := e.Status(); got != "unsealed" {
		t.Errorf("expected unsealed, got %s", got)
	}

	_ = v // silence unused warning
}
