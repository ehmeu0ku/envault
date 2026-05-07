package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempTTLDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-ttl-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLoadTTLIndex_EmptyOnMissing(t *testing.T) {
	dir := tempTTLDir(t)
	idx, err := LoadTTLIndex(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx) != 0 {
		t.Errorf("expected empty index, got %d entries", len(idx))
	}
}

func TestSetTTL_AndLoad(t *testing.T) {
	dir := tempTTLDir(t)
	filePath := filepath.Join(dir, "secrets.env.age")

	if err := SetTTL(dir, filePath, 24*time.Hour); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}

	idx, err := LoadTTLIndex(dir)
	if err != nil {
		t.Fatalf("LoadTTLIndex: %v", err)
	}
	entry, ok := idx[filePath]
	if !ok {
		t.Fatal("expected entry in index")
	}
	if entry.Path != filePath {
		t.Errorf("path mismatch: got %q", entry.Path)
	}
	if time.Until(entry.ExpiresAt) < 23*time.Hour {
		t.Errorf("expiry too soon: %v", entry.ExpiresAt)
	}
}

func TestIsExpired_NotExpired(t *testing.T) {
	dir := tempTTLDir(t)
	filePath := filepath.Join(dir, "a.env.age")

	if err := SetTTL(dir, filePath, time.Hour); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}
	expired, err := IsExpired(dir, filePath)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if expired {
		t.Error("expected not expired")
	}
}

func TestIsExpired_Expired(t *testing.T) {
	dir := tempTTLDir(t)
	filePath := filepath.Join(dir, "b.env.age")

	if err := SetTTL(dir, filePath, -time.Second); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}
	expired, err := IsExpired(dir, filePath)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if !expired {
		t.Error("expected expired")
	}
}

func TestPurgeExpired_RemovesFiles(t *testing.T) {
	dir := tempTTLDir(t)

	keepPath := filepath.Join(dir, "keep.env.age")
	purgePath := filepath.Join(dir, "purge.env.age")

	for _, p := range []string{keepPath, purgePath} {
		if err := os.WriteFile(p, []byte("data"), 0600); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	_ = SetTTL(dir, keepPath, time.Hour)
	_ = SetTTL(dir, purgePath, -time.Second)

	purged, err := PurgeExpired(dir)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if len(purged) != 1 || purged[0] != purgePath {
		t.Errorf("expected %q purged, got %v", purgePath, purged)
	}
	if _, err := os.Stat(purgePath); !os.IsNotExist(err) {
		t.Error("expected purged file to be removed")
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Errorf("keep file should still exist: %v", err)
	}
}

func TestIsExpired_NoEntry(t *testing.T) {
	dir := tempTTLDir(t)
	expired, err := IsExpired(dir, "nonexistent.env.age")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Error("missing entry should not be considered expired")
	}
}
