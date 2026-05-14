package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateRenameKeyTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealRenameKeyEnv(t *testing.T, dir, name, content string, rec age.Recipient) string {
	t.Helper()
	plain := filepath.Join(dir, name)
	enc := plain + ".age"
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := reEncrypt(enc, []byte(content), []age.Recipient{rec}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	_ = os.Remove(plain)
	return enc
}

func TestRenameKey_RenamesExistingKey(t *testing.T) {
	id, rec := generateRenameKeyTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRenameKeyEnv(t, dir, ".env", "FOO=bar\nBAZ=qux\n", rec)

	res, err := RenameKey(encPath, id, []age.Recipient{rec}, "FOO", "NEW_FOO", RenameKeyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Renamed {
		t.Fatal("expected Renamed=true")
	}

	pairs, err := decryptEnvPairs(encPath, id)
	if err != nil {
		t.Fatalf("decrypt after rename: %v", err)
	}
	keys := map[string]string{}
	for _, p := range pairs {
		keys[p[0]] = p[1]
	}
	if _, ok := keys["FOO"]; ok {
		t.Error("old key FOO still present")
	}
	if v, ok := keys["NEW_FOO"]; !ok || v != "bar" {
		t.Errorf("expected NEW_FOO=bar, got %q", v)
	}
}

func TestRenameKey_MissingKeyNoError(t *testing.T) {
	id, rec := generateRenameKeyTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRenameKeyEnv(t, dir, ".env", "FOO=bar\n", rec)

	res, err := RenameKey(encPath, id, []age.Recipient{rec}, "MISSING", "X", RenameKeyOptions{FailIfMissing: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Renamed {
		t.Error("expected Renamed=false for missing key")
	}
}

func TestRenameKey_MissingKeyFailIfMissing(t *testing.T) {
	id, rec := generateRenameKeyTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRenameKeyEnv(t, dir, ".env", "FOO=bar\n", rec)

	_, err := RenameKey(encPath, id, []age.Recipient{rec}, "MISSING", "X", RenameKeyOptions{FailIfMissing: true})
	if err == nil {
		t.Fatal("expected error for missing key with FailIfMissing=true")
	}
}

func TestRenameKey_MissingEncryptedFile(t *testing.T) {
	id, rec := generateRenameKeyTestIdentity(t)
	_, err := RenameKey("/nonexistent/.env.age", id, []age.Recipient{rec}, "A", "B", RenameKeyOptions{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
