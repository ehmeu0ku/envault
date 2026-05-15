package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateMaskTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealMaskEnv(t *testing.T, dir, name, content string, id *age.X25519Identity) string {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	v, err := New(dir, id.Recipient())
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	if err := v.Seal(plain); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return encryptedPath(plain)
}

func TestMask_AllKeysWhenNoFilter(t *testing.T) {
	dir := t.TempDir()
	id := generateMaskTestIdentity(t)
	enc := sealMaskEnv(t, dir, ".env", "SECRET=abc123\nNAME=alice\n", id)
	out := filepath.Join(dir, "masked.env")

	res, err := Mask(dir, enc, out, id, MaskOptions{})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if res.Masked != 2 {
		t.Errorf("want 2 masked, got %d", res.Masked)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "abc123") {
		t.Error("expected value to be masked")
	}
}

func TestMask_ByExplicitKey(t *testing.T) {
	dir := t.TempDir()
	id := generateMaskTestIdentity(t)
	enc := sealMaskEnv(t, dir, ".env", "SECRET=abc123\nNAME=alice\n", id)
	out := filepath.Join(dir, "masked.env")

	res, err := Mask(dir, enc, out, id, MaskOptions{Keys: []string{"SECRET"}})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if res.Masked != 1 || res.Skipped != 1 {
		t.Errorf("want 1 masked 1 skipped, got %d/%d", res.Masked, res.Skipped)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "abc123") {
		t.Error("SECRET value should be masked")
	}
	if !strings.Contains(string(data), "alice") {
		t.Error("NAME value should be revealed")
	}
}

func TestMask_ByPrefix(t *testing.T) {
	dir := t.TempDir()
	id := generateMaskTestIdentity(t)
	enc := sealMaskEnv(t, dir, ".env", "DB_PASS=secret\nDB_HOST=localhost\nAPP_NAME=foo\n", id)
	out := filepath.Join(dir, "masked.env")

	res, err := Mask(dir, enc, out, id, MaskOptions{Prefix: "DB_"})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if res.Masked != 2 {
		t.Errorf("want 2 masked, got %d", res.Masked)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "secret") {
		t.Error("DB_PASS should be masked")
	}
	if !strings.Contains(string(data), "foo") {
		t.Error("APP_NAME should be revealed")
	}
}

func TestMask_RevealFirstChars(t *testing.T) {
	dir := t.TempDir()
	id := generateMaskTestIdentity(t)
	enc := sealMaskEnv(t, dir, ".env", "TOKEN=abcdef\n", id)
	out := filepath.Join(dir, "masked.env")

	_, err := Mask(dir, enc, out, id, MaskOptions{Reveal: 2})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "ab****") {
		t.Errorf("expected partial reveal, got: %s", string(data))
	}
}

func TestMask_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id := generateMaskTestIdentity(t)
	_, err := Mask(dir, filepath.Join(dir, "nonexistent.env.age"), "", id, MaskOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}
