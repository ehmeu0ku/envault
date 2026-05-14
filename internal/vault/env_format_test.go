package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/cipherlock/envault/internal/crypto"
)

func generateFormatTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealFormatEnv(t *testing.T, dir, name, content string, recipient age.Recipient) {
	t.Helper()
	v := New(dir)
	encPath := v.encryptedPath(name)
	if err := os.MkdirAll(filepath.Dir(encPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := crypto.EncryptFile(encPath, []byte(content), []age.Recipient{recipient}); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func decryptFormatEnv(t *testing.T, dir, name string, identity age.Identity) string {
	t.Helper()
	v := New(dir)
	data, err := crypto.DecryptFile(v.encryptedPath(name), identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(data)
}

func TestFormat_SortKeys(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFormatTestIdentity(t)
	content := "ZEBRA=1\nAPPLE=2\nMIDDLE=3\n"
	sealFormatEnv(t, dir, ".env", content, rec)

	_, err := Format(dir, ".env", id, []age.Recipient{rec}, FormatOptions{SortKeys: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	out := decryptFormatEnv(t, dir, ".env", id)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[0] != "APPLE=2" || lines[1] != "MIDDLE=3" || lines[2] != "ZEBRA=1" {
		t.Errorf("keys not sorted: %v", lines)
	}
}

func TestFormat_StripBlanks(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFormatTestIdentity(t)
	content := "KEY=val\n\n\nOTHER=x\n"
	sealFormatEnv(t, dir, ".env", content, rec)

	res, err := Format(dir, ".env", id, []age.Recipient{rec}, FormatOptions{StripBlanks: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if res.BlanksRemoved != 2 {
		t.Errorf("expected 2 blanks removed, got %d", res.BlanksRemoved)
	}
	out := decryptFormatEnv(t, dir, ".env", id)
	if strings.Contains(out, "\n\n") {
		t.Error("blank lines not removed")
	}
}

func TestFormat_NormalizeQuotes(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFormatTestIdentity(t)
	content := `KEY="hello"` + "\n" + `OTHER='world'` + "\n"
	sealFormatEnv(t, dir, ".env", content, rec)

	res, err := Format(dir, ".env", id, []age.Recipient{rec}, FormatOptions{NormalizeQuotes: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if res.QuotesNormalized != 2 {
		t.Errorf("expected 2 quotes normalized, got %d", res.QuotesNormalized)
	}
	out := decryptFormatEnv(t, dir, ".env", id)
	if strings.Contains(out, `"`) || strings.Contains(out, "'") {
		t.Error("quotes not stripped")
	}
}

func TestFormat_MissingFile(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFormatTestIdentity(t)
	_, err := Format(dir, ".env", id, []age.Recipient{rec}, FormatOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}
