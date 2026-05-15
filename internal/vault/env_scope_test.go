package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateScopeTestIdentity(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealScopeEnv(t *testing.T, dir, name, content string, rec *age.X25519Recipient) {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	enc := encryptedPath(plain)
	if err := EncryptFile(plain, enc, []age.Recipient{rec}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	os.Remove(plain)
}

func TestScope_PrefixesKeys(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateScopeTestIdentity(t)

	src := filepath.Join(dir, ".env")
	dst := filepath.Join(dir, ".env.prod")
	sealScopeEnv(t, dir, ".env", "DB_HOST=localhost\nDB_PORT=5432\n", rec)

	result, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "prod"})
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if result.Added != 2 {
		t.Errorf("expected 2 added, got %d", result.Added)
	}

	pairs, err := decryptEnvPairs(encryptedPath(dst), id)
	if err != nil {
		t.Fatalf("decrypt dest: %v", err)
	}
	joined := strings.Join(pairs, "\n")
	if !strings.Contains(joined, "PROD_DB_HOST=localhost") {
		t.Errorf("missing PROD_DB_HOST, got: %s", joined)
	}
	if !strings.Contains(joined, "PROD_DB_PORT=5432") {
		t.Errorf("missing PROD_DB_PORT, got: %s", joined)
	}
}

func TestScope_EmptyPrefixReturnsError(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateScopeTestIdentity(t)
	src := filepath.Join(dir, ".env")
	dst := filepath.Join(dir, ".env.out")
	_, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: ""})
	if err == nil {
		t.Fatal("expected error for empty prefix")
	}
}

func TestScope_MissingSourceReturnsError(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateScopeTestIdentity(t)
	src := filepath.Join(dir, ".env.missing")
	dst := filepath.Join(dir, ".env.out")
	_, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "staging"})
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestScope_NoOverwriteBlocksExisting(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateScopeTestIdentity(t)

	src := filepath.Join(dir, ".env")
	dst := filepath.Join(dir, ".env.scoped")
	sealScopeEnv(t, dir, ".env", "KEY=val\n", rec)

	// First scope succeeds.
	if _, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "dev"}); err != nil {
		t.Fatalf("first scope: %v", err)
	}
	// Second without overwrite should fail.
	_, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "dev"})
	if err == nil {
		t.Fatal("expected error when destination exists and overwrite=false")
	}
}

func TestScope_OverwriteReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateScopeTestIdentity(t)

	src := filepath.Join(dir, ".env")
	dst := filepath.Join(dir, ".env.scoped")
	sealScopeEnv(t, dir, ".env", "KEY=val\n", rec)

	if _, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "dev"}); err != nil {
		t.Fatalf("first scope: %v", err)
	}
	_, err := Scope(dir, src, dst, []age.Recipient{rec}, id, ScopeOptions{Prefix: "dev", Overwrite: true})
	if err != nil {
		t.Fatalf("overwrite scope: %v", err)
	}
}
