package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateImportTestIdentity(t *testing.T) (*age.X25519Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func TestImport_FreshVault(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id, rec := generateImportTestIdentity(t)
	v.identities = []age.Identity{id}

	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "FOO=bar\nBAZ=qux\n")

	res, err := v.Import(envFile, rec, false)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", res.Imported)
	}
	if res.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", res.Skipped)
	}
}

func TestImport_SkipsExistingKeys(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id, rec := generateImportTestIdentity(t)
	v.identities = []age.Identity{id}

	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "FOO=original\n")

	if _, err := v.Import(envFile, rec, false); err != nil {
		t.Fatalf("first import: %v", err)
	}

	writeEnvFile(t, envFile, "FOO=changed\nNEW=value\n")
	res, err := v.Import(envFile, rec, false)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", res.Skipped)
	}
	if res.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", res.Imported)
	}
}

func TestImport_OverwriteExistingKeys(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id, rec := generateImportTestIdentity(t)
	v.identities = []age.Identity{id}

	envFile := filepath.Join(dir, ".env")
	writeEnvFile(t, envFile, "FOO=original\n")
	if _, err := v.Import(envFile, rec, false); err != nil {
		t.Fatalf("first import: %v", err)
	}

	writeEnvFile(t, envFile, "FOO=updated\n")
	res, err := v.Import(envFile, rec, true)
	if err != nil {
		t.Fatalf("overwrite import: %v", err)
	}
	if res.Imported != 1 || res.Skipped != 0 {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestImport_MissingSourceFile(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	_, rec := generateImportTestIdentity(t)

	_, err := v.Import(filepath.Join(dir, "nonexistent.env"), rec, false)
	if err == nil {
		t.Fatal("expected error for missing source file")
	}
}

func TestReadEnvPairs_IgnoresComments(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	os.WriteFile(f, []byte("# comment\nKEY=val\n\nOTHER='quoted'\n"), 0600)

	pairs, err := readEnvPairs(f)
	if err != nil {
		t.Fatalf("readEnvPairs: %v", err)
	}
	if len(pairs) != 2 {
		t.Errorf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[1][1] != "quoted" {
		t.Errorf("expected unquoted value, got %q", pairs[1][1])
	}
}
