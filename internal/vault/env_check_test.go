package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateCheckTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestCheckEnv_AllKeysPresent(t *testing.T) {
	dir := t.TempDir()
	id := generateCheckTestIdentity(t)

	v := New(dir)
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(envFile, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}

	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := v.CheckEnv(envFile, identityFile, []string{"FOO", "BAZ"})
	if err != nil {
		t.Fatalf("CheckEnv: %v", err)
	}
	if len(report.Missing) != 0 {
		t.Errorf("expected no missing keys, got %v", report.Missing)
	}
	if len(report.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Results))
	}
}

func TestCheckEnv_MissingKey(t *testing.T) {
	dir := t.TempDir()
	id := generateCheckTestIdentity(t)

	v := New(dir)
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(envFile, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}

	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := v.CheckEnv(envFile, identityFile, []string{"FOO", "MISSING_KEY"})
	if err != nil {
		t.Fatalf("CheckEnv: %v", err)
	}
	if len(report.Missing) != 1 || report.Missing[0] != "MISSING_KEY" {
		t.Errorf("expected MISSING_KEY in missing list, got %v", report.Missing)
	}
}

func TestCheckEnv_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id := generateCheckTestIdentity(t)

	v := New(dir)
	envFile := filepath.Join(dir, ".env")

	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := v.CheckEnv(envFile, identityFile, []string{"FOO"})
	if err == nil {
		t.Fatal("expected error for missing encrypted file")
	}
}

func TestCheckEnv_NoKeysFiltersAll(t *testing.T) {
	dir := t.TempDir()
	id := generateCheckTestIdentity(t)

	v := New(dir)
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Seal(envFile, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}

	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := v.CheckEnv(envFile, identityFile, nil)
	if err != nil {
		t.Fatalf("CheckEnv: %v", err)
	}
	if len(report.Results) != 3 {
		t.Errorf("expected 3 results for all keys, got %d", len(report.Results))
	}
}
