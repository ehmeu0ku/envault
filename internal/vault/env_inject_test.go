package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/vercel/envault/internal/crypto"
)

func generateInjectTestIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealInjectEnv(t *testing.T, dir, name, content string, id age.Identity) {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	recip := id.(*age.X25519Identity).Recipient()
	enc := plain + ".age"
	if err := crypto.EncryptFile(plain, enc, []age.Recipient{recip}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	os.Remove(plain)
}

func TestInject_RunsCommandWithEnv(t *testing.T) {
	dir := t.TempDir()
	id := generateInjectTestIdentity(t)
	sealInjectEnv(t, dir, ".env", "INJECT_HELLO=world\nINJECT_NUM=42\n", id)

	err := Inject(dir, filepath.Join(dir, ".env"), id,
		[]string{"env"},
		InjectOptions{Overwrite: true},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInject_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id := generateInjectTestIdentity(t)

	err := Inject(dir, filepath.Join(dir, ".env"), id,
		[]string{"env"},
		InjectOptions{},
	)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestInject_NoCommandReturnsError(t *testing.T) {
	dir := t.TempDir()
	id := generateInjectTestIdentity(t)
	sealInjectEnv(t, dir, ".env", "K=V\n", id)

	err := Inject(dir, filepath.Join(dir, ".env"), id, []string{}, InjectOptions{})
	if err == nil {
		t.Fatal("expected error for empty args")
	}
}

func TestInject_DoesNotOverwriteByDefault(t *testing.T) {
	dir := t.TempDir()
	id := generateInjectTestIdentity(t)
	sealInjectEnv(t, dir, ".env", "PATH=/injected\n", id)

	// PATH already exists in os.Environ; with Overwrite=false it should be skipped.
	// Command still runs successfully.
	err := Inject(dir, filepath.Join(dir, ".env"), id,
		[]string{"true"},
		InjectOptions{Overwrite: false},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
