package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateLintTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestLint_CleanFile(t *testing.T) {
	id := generateLintTestIdentity(t)
	v := tempVaultWithIdentity(t, id)

	env := filepath.Join(v.dir, ".env")
	writeEnvFile(t, env, "KEY1=value1\nKEY2=value2\n")
	if err := v.Seal(env); err != nil {
		t.Fatalf("seal: %v", err)
	}

	res, err := v.Lint(env)
	if err != nil {
		t.Fatalf("lint error: %v", err)
	}
	if !res.OK() {
		t.Errorf("expected no issues, got: %v", res.Issues)
	}
}

func TestLint_DuplicateKey(t *testing.T) {
	id := generateLintTestIdentity(t)
	v := tempVaultWithIdentity(t, id)

	env := filepath.Join(v.dir, ".env")
	writeEnvFile(t, env, "KEY=first\nKEY=second\n")
	if err := v.Seal(env); err != nil {
		t.Fatalf("seal: %v", err)
	}

	res, err := v.Lint(env)
	if err != nil {
		t.Fatalf("lint error: %v", err)
	}
	if res.OK() {
		t.Fatal("expected duplicate key issue")
	}
	if !containsMsg(res.Issues, "duplicate") {
		t.Errorf("expected duplicate message, got %v", res.Issues)
	}
}

func TestLint_EmptyValue(t *testing.T) {
	id := generateLintTestIdentity(t)
	v := tempVaultWithIdentity(t, id)

	env := filepath.Join(v.dir, ".env")
	writeEnvFile(t, env, "KEY=\n")
	if err := v.Seal(env); err != nil {
		t.Fatalf("seal: %v", err)
	}

	res, err := v.Lint(env)
	if err != nil {
		t.Fatalf("lint error: %v", err)
	}
	if !containsMsg(res.Issues, "empty value") {
		t.Errorf("expected empty value issue, got %v", res.Issues)
	}
}

func TestLint_MissingEncryptedFile(t *testing.T) {
	id := generateLintTestIdentity(t)
	v := tempVaultWithIdentity(t, id)

	env := filepath.Join(v.dir, ".env")
	_, err := v.Lint(env)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func containsMsg(issues []LintIssue, sub string) bool {
	for _, iss := range issues {
		if strings.Contains(iss.Message, sub) {
			return true
		}
	}
	return false
}

func tempVaultWithIdentity(t *testing.T, id *age.X25519Identity) *Vault {
	t.Helper()
	dir, err := os.MkdirTemp("", "vault-lint-*")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return New(dir, id)
}
