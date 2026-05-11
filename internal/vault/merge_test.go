package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateMergeTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func setupMergeVault(t *testing.T, id age.Identity, rec age.Recipient) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v := New(dir)
	return v, dir
}

func writeSealedEnv(t *testing.T, v *Vault, name, content string, rec age.Recipient) {
	t.Helper()
	tmp, err := os.CreateTemp("", "envault-test-*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()

	plain := filepath.Join(v.dir, name)
	if err := os.WriteFile(plain, []byte(content), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := v.Seal(name, rec); err != nil {
		t.Fatalf("seal %s: %v", name, err)
	}
	os.Remove(plain)
}

func TestMerge_AddsNewKeys(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "FOO=foo\nBAR=bar\n", rec)
	writeSealedEnv(t, v, ".env.prod", "BAZ=baz\n", rec)

	res, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategySkip)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(res.Added) != 2 {
		t.Errorf("expected 2 added, got %d: %v", len(res.Added), res.Added)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("expected 0 skipped, got %d", len(res.Skipped))
	}
}

func TestMerge_SkipsConflictingKeys(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "FOO=src_value\n", rec)
	writeSealedEnv(t, v, ".env.prod", "FOO=dst_value\n", rec)

	res, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategySkip)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "FOO" {
		t.Errorf("expected FOO skipped, got %v", res.Skipped)
	}
}

func TestMerge_OverwritesConflictingKeys(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "FOO=new_value\n", rec)
	writeSealedEnv(t, v, ".env.prod", "FOO=old_value\n", rec)

	res, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategyOverwrite)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(res.Overwritten) != 1 || res.Overwritten[0] != "FOO" {
		t.Errorf("expected FOO overwritten, got %v", res.Overwritten)
	}
}

func TestMerge_MissingSourceFile(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env.prod", "FOO=bar\n", rec)

	_, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategySkip)
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

func TestMerge_MissingDestinationFile(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "FOO=bar\n", rec)

	_, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategySkip)
	if err == nil {
		t.Fatal("expected error for missing destination, got nil")
	}
}
