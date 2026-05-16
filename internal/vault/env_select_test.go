package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/vercel/envault/internal/crypto"
)

func generateSelectTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealSelectEnv(t *testing.T, dir, name, content string, rec age.Recipient) string {
	t.Helper()
	encPath := filepath.Join(dir, name+".age")
	if err := crypto.EncryptFile([]byte(content), encPath, []age.Recipient{rec}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return encPath
}

func TestSelect_ByExplicitKeys(t *testing.T) {
	id, rec := generateSelectTestIdentity(t)
	dir := t.TempDir()

	src := sealSelectEnv(t, dir, "prod", "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=secret\n", rec)
	out := filepath.Join(dir, "selected.age")

	res, err := Select(dir, src, out, []age.Recipient{rec}, id, SelectOptions{
		Keys: []string{"DB_HOST", "API_KEY"},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if res.Included != 2 || res.Excluded != 1 {
		t.Errorf("expected included=2 excluded=1, got %+v", res)
	}

	plain, err := crypto.DecryptFile(out, id)
	if err != nil {
		t.Fatalf("decrypt result: %v", err)
	}
	if !containsHelper(string(plain), "DB_HOST=") || !containsHelper(string(plain), "API_KEY=") {
		t.Errorf("expected DB_HOST and API_KEY in output, got:\n%s", plain)
	}
	if containsHelper(string(plain), "DB_PORT=") {
		t.Errorf("DB_PORT should have been excluded")
	}
}

func TestSelect_ByPrefix(t *testing.T) {
	id, rec := generateSelectTestIdentity(t)
	dir := t.TempDir()

	src := sealSelectEnv(t, dir, "prod", "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=secret\n", rec)
	out := filepath.Join(dir, "db_only.age")

	res, err := Select(dir, src, out, []age.Recipient{rec}, id, SelectOptions{
		Prefixes: []string{"DB_"},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if res.Included != 2 || res.Excluded != 1 {
		t.Errorf("expected included=2 excluded=1, got %+v", res)
	}
}

func TestSelect_Invert(t *testing.T) {
	id, rec := generateSelectTestIdentity(t)
	dir := t.TempDir()

	src := sealSelectEnv(t, dir, "prod", "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=secret\n", rec)
	out := filepath.Join(dir, "no_db.age")

	res, err := Select(dir, src, out, []age.Recipient{rec}, id, SelectOptions{
		Prefixes: []string{"DB_"},
		Invert:   true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if res.Included != 1 || res.Excluded != 2 {
		t.Errorf("expected included=1 excluded=2, got %+v", res)
	}

	plain, err := crypto.DecryptFile(out, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !containsHelper(string(plain), "API_KEY=") {
		t.Errorf("expected API_KEY in inverted output")
	}
}

func TestSelect_NoRecipients(t *testing.T) {
	id, rec := generateSelectTestIdentity(t)
	dir := t.TempDir()
	src := sealSelectEnv(t, dir, "prod", "KEY=val\n", rec)
	out := filepath.Join(dir, "out.age")

	_, err := Select(dir, src, out, nil, id, SelectOptions{Keys: []string{"KEY"}})
	if err == nil {
		t.Fatal("expected error with no recipients")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("output file should not have been created")
	}
}

func TestSelect_MissingSourceFile(t *testing.T) {
	id, rec := generateSelectTestIdentity(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out.age")

	_, err := Select(dir, filepath.Join(dir, "missing.age"), out, []age.Recipient{rec}, id, SelectOptions{})
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}
