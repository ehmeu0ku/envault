package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func tempSignDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-sign-*")
	if err != nil {
		t.Fatalf("tempSignDir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeSignFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeSignFile: %v", err)
	}
	return path
}

func TestLoadSignatures_EmptyOnMissing(t *testing.T) {
	dir := tempSignDir(t)
	records, err := LoadSignatures(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected empty map, got %d entries", len(records))
	}
}

func TestSignFile_CreatesRecord(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "dev.env.age", "encrypted-content")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	records, err := LoadSignatures(dir)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
}

func TestVerifySignature_Valid(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "prod.env.age", "some-encrypted-bytes")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if err := VerifySignature(dir, path, key); err != nil {
		t.Errorf("VerifySignature: expected valid, got %v", err)
	}
}

func TestVerifySignature_Tampered(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "staging.env.age", "original-content")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	// Tamper with the file
	if err := os.WriteFile(path, []byte("tampered-content"), 0600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	if err := VerifySignature(dir, path, key); err == nil {
		t.Error("expected signature mismatch error, got nil")
	}
}

func TestVerifySignature_MissingRecord(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "unknown.env.age", "data")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := VerifySignature(dir, path, key); err == nil {
		t.Error("expected error for missing record, got nil")
	}
}

func TestSignFile_WrongKey(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "ci.env.age", "encrypted")
	key1 := []byte("key-one-32-bytes-long-padded!!!!")
	key2 := []byte("key-two-32-bytes-long-padded!!!!")

	if err := SignFile(dir, path, key1); err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if err := VerifySignature(dir, path, key2); err == nil {
		t.Error("expected mismatch with wrong key, got nil")
	}
}
