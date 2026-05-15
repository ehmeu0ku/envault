package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateTrimTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealTrimEnv(t *testing.T, dir, name, content string, recipient age.Recipient) string {
	t.Helper()
	v := New(dir)
	plain := filepath.Join(dir, name+".env")
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := v.Seal(plain, recipient); err != nil {
		t.Fatalf("seal: %v", err)
	}
	os.Remove(plain)
	return filepath.Join(dir, name+".env.age")
}

func TestTrim_TrimSpace(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateTrimTestIdentity(t)
	enc := sealTrimEnv(t, dir, "test", "FOO=  hello  \nBAR=world\n", rec)

	res, err := Trim(enc, id, rec, TrimOptions{TrimSpace: true})
	if err != nil {
		t.Fatalf("Trim: %v", err)
	}
	if res.Trimmed != 1 {
		t.Errorf("expected 1 trimmed, got %d", res.Trimmed)
	}

	pairs, err := decryptEnvPairs(enc, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for _, p := range pairs {
		if strings.HasPrefix(p, "FOO=") && strings.Contains(p, "  ") {
			t.Errorf("expected whitespace stripped, got %q", p)
		}
	}
}

func TestTrim_RemoveQuotes(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateTrimTestIdentity(t)
	enc := sealTrimEnv(t, dir, "test", `FOO="quoted"
BAR='single'
BAZ=plain
`, rec)

	res, err := Trim(enc, id, rec, TrimOptions{RemoveQuotes: true})
	if err != nil {
		t.Fatalf("Trim: %v", err)
	}
	if res.Unquoted != 2 {
		t.Errorf("expected 2 unquoted, got %d", res.Unquoted)
	}

	pairs, err := decryptEnvPairs(enc, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for _, p := range pairs {
		if strings.Contains(p, `"`) || (strings.Contains(p, "'") && !strings.HasPrefix(p, "BAZ")) {
			t.Errorf("unexpected quote in %q", p)
		}
	}
}

func TestTrim_NormalizeKeys(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateTrimTestIdentity(t)
	enc := sealTrimEnv(t, dir, "test", "foo=bar\nBaz=qux\nALREADY=ok\n", rec)

	res, err := Trim(enc, id, rec, TrimOptions{NormalizeKeys: true})
	if err != nil {
		t.Fatalf("Trim: %v", err)
	}
	if res.Renamed != 2 {
		t.Errorf("expected 2 renamed, got %d", res.Renamed)
	}

	pairs, err := decryptEnvPairs(enc, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for _, p := range pairs {
		key, _, _ := strings.Cut(p, "=")
		if key != strings.ToUpper(key) {
			t.Errorf("key not uppercased: %q", key)
		}
	}
}

func TestTrim_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateTrimTestIdentity(t)
	_, err := Trim(filepath.Join(dir, "missing.env.age"), id, rec, TrimOptions{TrimSpace: true})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
