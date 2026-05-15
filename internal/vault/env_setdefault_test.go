package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateSetDefaultTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealSetDefaultEnv(t *testing.T, dir, name, content string, rec age.Recipient) string {
	t.Helper()
	encPath := filepath.Join(dir, name+".age")
	if err := encryptToFile([]byte(content), encPath, rec); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return encPath
}

func TestSetDefault_AddsMissingKeys(t *testing.T) {
	id, rec := generateSetDefaultTestIdentity(t)
	dir := t.TempDir()

	encPath := sealSetDefaultEnv(t, dir, ".env", "FOO=bar\n", rec)

	result, err := SetDefault(dir, encPath, map[string]string{
		"BAZ": "qux",
		"FOO": "ignored",
	}, id, rec, SetDefaultOptions{})
	if err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	if len(result.Set) != 1 || result.Set[0] != "BAZ" {
		t.Errorf("expected Set=[BAZ], got %v", result.Set)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "FOO" {
		t.Errorf("expected Skipped=[FOO], got %v", result.Skipped)
	}

	pairs, err := decryptEnvPairs(encPath, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	m := make(map[string]string)
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	if m["FOO"] != "bar" {
		t.Errorf("FOO should remain bar, got %q", m["FOO"])
	}
	if m["BAZ"] != "qux" {
		t.Errorf("BAZ should be qux, got %q", m["BAZ"])
	}
}

func TestSetDefault_OverwriteExistingKeys(t *testing.T) {
	id, rec := generateSetDefaultTestIdentity(t)
	dir := t.TempDir()

	encPath := sealSetDefaultEnv(t, dir, ".env", "FOO=old\n", rec)

	_, err := SetDefault(dir, encPath, map[string]string{"FOO": "new"}, id, rec,
		SetDefaultOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	pairs, _ := decryptEnvPairs(encPath, id)
	for _, p := range pairs {
		if p[0] == "FOO" && p[1] != "new" {
			t.Errorf("expected FOO=new, got %q", p[1])
		}
	}
}

func TestSetDefault_MissingFileReturnsError(t *testing.T) {
	id, rec := generateSetDefaultTestIdentity(t)
	dir := t.TempDir()

	_, err := SetDefault(dir, filepath.Join(dir, "missing.age"),
		map[string]string{"X": "y"}, id, rec, SetDefaultOptions{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSetDefault_WrongSuffixReturnsError(t *testing.T) {
	id, rec := generateSetDefaultTestIdentity(t)
	dir := t.TempDir()
	plain := filepath.Join(dir, ".env")
	_ = os.WriteFile(plain, []byte("A=1\n"), 0600)

	_, err := SetDefault(dir, plain, map[string]string{"B": "2"}, id, rec, SetDefaultOptions{})
	if err == nil {
		t.Fatal("expected error for non-.age path")
	}
}
