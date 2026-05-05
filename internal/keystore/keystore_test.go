package keystore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/envault/internal/keystore"
)

func tempKeyStore(t *testing.T) *keystore.KeyStore {
	t.Helper()
	dir := t.TempDir()
	ks, err := keystore.New(filepath.Join(dir, ".envault"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ks
}

func TestGenerate_CreatesFile(t *testing.T) {
	ks := tempKeyStore(t)
	id, err := ks.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity")
	}
	if _, err := os.Stat(ks.KeyPath()); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
}

func TestGenerate_FilePermissions(t *testing.T) {
	ks := tempKeyStore(t)
	if _, err := ks.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	info, err := os.Stat(ks.KeyPath())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %v", info.Mode().Perm())
	}
}

func TestGenerate_ErrorIfExists(t *testing.T) {
	ks := tempKeyStore(t)
	if _, err := ks.Generate(); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	_, err := ks.Generate()
	if err == nil {
		t.Fatal("expected error on second Generate, got nil")
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	ks := tempKeyStore(t)
	original, err := ks.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	loaded, err := ks.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if original.Recipient().String() != loaded.Recipient().String() {
		t.Errorf("recipient mismatch: got %q, want %q",
			loaded.Recipient().String(), original.Recipient().String())
	}
}

func TestLoad_ErrorIfMissing(t *testing.T) {
	ks := tempKeyStore(t)
	_, err := ks.Load()
	if err == nil {
		t.Fatal("expected error loading non-existent key, got nil")
	}
}

func TestExists(t *testing.T) {
	ks := tempKeyStore(t)
	if ks.Exists() {
		t.Fatal("Exists should be false before Generate")
	}
	if _, err := ks.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !ks.Exists() {
		t.Fatal("Exists should be true after Generate")
	}
}
