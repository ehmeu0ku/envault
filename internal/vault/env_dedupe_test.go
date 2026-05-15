package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/nicholasgasior/envault/internal/crypto"
)

func generateDedupeTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealDedupeEnv(t *testing.T, dir, content string, recipient age.Recipient) string {
	t.Helper()
	encPath := filepath.Join(dir, ".env.age")
	if err := crypto.EncryptFile([]byte(content), encPath, recipient); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return encPath
}

func TestDedupe_NoDuplicates(t *testing.T) {
	id, rec := generateDedupeTestIdentity(t)
	dir := t.TempDir()

	encPath := sealDedupeEnv(t, dir, "FOO=bar\nBAZ=qux\n", rec)

	res, err := Dedupe(encPath, id, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Errorf("expected no removals, got %v", res.Removed)
	}
	if len(res.Kept) != 2 {
		t.Errorf("expected 2 kept keys, got %d", len(res.Kept))
	}
}

func TestDedupe_RemovesDuplicateKey(t *testing.T) {
	id, rec := generateDedupeTestIdentity(t)
	dir := t.TempDir()

	// FOO appears twice; last value should win
	encPath := sealDedupeEnv(t, dir, "FOO=first\nBAR=keep\nFOO=second\n", rec)

	res, err := Dedupe(encPath, id, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "FOO" {
		t.Errorf("expected [FOO] removed, got %v", res.Removed)
	}
	if res.Kept["FOO"] != "second" {
		t.Errorf("expected FOO=second, got %q", res.Kept["FOO"])
	}
	if res.Kept["BAR"] != "keep" {
		t.Errorf("expected BAR=keep, got %q", res.Kept["BAR"])
	}
}

func TestDedupe_MissingFile(t *testing.T) {
	id, rec := generateDedupeTestIdentity(t)
	dir := t.TempDir()

	_, err := Dedupe(filepath.Join(dir, "missing.age"), id, rec)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDedupe_ReEncryptsResult(t *testing.T) {
	id, rec := generateDedupeTestIdentity(t)
	dir := t.TempDir()

	encPath := sealDedupeEnv(t, dir, "A=1\nB=2\nA=3\n", rec)

	if _, err := Dedupe(encPath, id, rec); err != nil {
		t.Fatalf("dedupe: %v", err)
	}

	// Verify the file is still readable after re-encryption
	if _, err := os.Stat(encPath); err != nil {
		t.Fatalf("encrypted file missing after dedupe: %v", err)
	}

	plain, err := crypto.DecryptFile(encPath, id)
	if err != nil {
		t.Fatalf("decrypt after dedupe: %v", err)
	}
	if string(plain) == "" {
		t.Error("decrypted content is empty")
	}
}
