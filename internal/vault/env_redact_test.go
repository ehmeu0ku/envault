package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateRedactTestIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealRedactEnv(t *testing.T, dir, name, content string, id age.Identity) string {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	v, err := New(dir)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	recip := id.(*age.X25519Identity).Recipient()
	if err := v.Seal(name, recip); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return filepath.Join(dir, name+".age")
}

func TestRedact_MasksValues(t *testing.T) {
	id := generateRedactTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRedactEnv(t, dir, ".env", "SECRET=hunter2\nAPI_KEY=abc123\n", id)

	res, err := Redact(encPath, id, RedactOptions{ShowKeys: true})
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	for _, line := range res.Lines {
		if strings.Contains(line, "hunter2") || strings.Contains(line, "abc123") {
			t.Errorf("value not masked in line: %s", line)
		}
	}
}

func TestRedact_RevealKeys(t *testing.T) {
	id := generateRedactTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRedactEnv(t, dir, ".env", "PUBLIC=visible\nSECRET=hidden\n", id)

	res, err := Redact(encPath, id, RedactOptions{
		ShowKeys:   true,
		RevealKeys: []string{"PUBLIC"},
	})
	if err != nil {
		t.Fatalf("redact: %v", err)
	}

	found := false
	for _, line := range res.Lines {
		if strings.HasPrefix(line, "PUBLIC=") {
			if !strings.Contains(line, "visible") {
				t.Errorf("PUBLIC should be revealed, got: %s", line)
			}
			found = true
		}
		if strings.HasPrefix(line, "SECRET=") && strings.Contains(line, "hidden") {
			t.Errorf("SECRET should be masked, got: %s", line)
		}
	}
	if !found {
		t.Error("PUBLIC key not found in output")
	}
}

func TestRedact_RedactsKeyNames(t *testing.T) {
	id := generateRedactTestIdentity(t)
	dir := t.TempDir()
	encPath := sealRedactEnv(t, dir, ".env", "DATABASE_URL=postgres://secret\n", id)

	res, err := Redact(encPath, id, RedactOptions{ShowKeys: false})
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(res.Lines) == 0 {
		t.Fatal("expected at least one line")
	}
	if strings.Contains(res.Lines[0], "DATABASE_URL") {
		t.Errorf("key name should be partially redacted, got: %s", res.Lines[0])
	}
}

func TestRedact_MissingFile(t *testing.T) {
	id := generateRedactTestIdentity(t)
	_, err := Redact("/nonexistent/.env.age", id, RedactOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRedact_WrongSuffix(t *testing.T) {
	id := generateRedactTestIdentity(t)
	_, err := Redact("/some/.env", id, RedactOptions{})
	if err == nil {
		t.Error("expected error for non-.age file")
	}
}

func TestMaskValue_Empty(t *testing.T) {
	if got := maskValue("", "*"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestRedactKey_Short(t *testing.T) {
	if got := redactKey("AB"); got != "AB" {
		t.Errorf("short key should be unchanged, got %q", got)
	}
}
