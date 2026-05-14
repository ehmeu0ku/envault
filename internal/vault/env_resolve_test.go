package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/subtlepseudonym/envault/internal/crypto"
)

func generateResolveTestIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealResolveEnv(t *testing.T, dir, name, content string, id age.Identity) {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	enc := filepath.Join(dir, name+".age")
	recip := id.(*age.X25519Identity).Recipient()
	if err := crypto.EncryptFile(plain, enc, recip); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	os.Remove(plain)
}

func TestResolve_NoReferences(t *testing.T) {
	id := generateResolveTestIdentity(t)
	dir := t.TempDir()
	sealResolveEnv(t, dir, ".env", "FOO=bar\nBAZ=qux\n", id)

	res, err := Resolve(dir, ".env", id, ResolveOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(res.Pairs))
	}
	if res.Resolved != 0 {
		t.Errorf("expected 0 resolved, got %d", res.Resolved)
	}
}

func TestResolve_InternalReference(t *testing.T) {
	id := generateResolveTestIdentity(t)
	dir := t.TempDir()
	sealResolveEnv(t, dir, ".env", "BASE=/opt/app\nDATA=${BASE}/data\n", id)

	res, err := Resolve(dir, ".env", id, ResolveOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Resolved != 1 {
		t.Errorf("expected 1 resolved, got %d", res.Resolved)
	}
	for _, p := range res.Pairs {
		if p.Key == "DATA" && p.Value != "/opt/app/data" {
			t.Errorf("DATA = %q, want /opt/app/data", p.Value)
		}
	}
}

func TestResolve_FallbackToEnv(t *testing.T) {
	id := generateResolveTestIdentity(t)
	dir := t.TempDir()
	t.Setenv("HOST_PORT", "8080")
	sealResolveEnv(t, dir, ".env", "ADDR=localhost:${HOST_PORT}\n", id)

	res, err := Resolve(dir, ".env", id, ResolveOptions{FallbackToEnv: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Resolved != 1 {
		t.Errorf("expected 1 resolved, got %d", res.Resolved)
	}
	if res.Pairs[0].Value != "localhost:8080" {
		t.Errorf("ADDR = %q, want localhost:8080", res.Pairs[0].Value)
	}
}

func TestResolve_FailOnMissing(t *testing.T) {
	id := generateResolveTestIdentity(t)
	dir := t.TempDir()
	sealResolveEnv(t, dir, ".env", "KEY=${UNDEFINED_VAR}\n", id)

	_, err := Resolve(dir, ".env", id, ResolveOptions{FailOnMissing: true})
	if err == nil {
		t.Fatal("expected error for missing variable, got nil")
	}
	if !strings.Contains(err.Error(), "UNDEFINED_VAR") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

func TestResolve_MissingEncryptedFile(t *testing.T) {
	id := generateResolveTestIdentity(t)
	dir := t.TempDir()

	_, err := Resolve(dir, ".env", id, ResolveOptions{})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
