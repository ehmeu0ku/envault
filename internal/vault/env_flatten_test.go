package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateFlattenTestIdentity(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealFlattenEnv(t *testing.T, dir, name, content string, recipient age.Recipient) {
	t.Helper()
	v := New(dir)
	envPath := filepath.Join(dir, name)
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := v.Seal(envPath, recipient); err != nil {
		t.Fatalf("seal: %v", err)
	}
	os.Remove(envPath)
}

func decryptFlattenEnv(t *testing.T, encPath string, identity age.Identity) string {
	t.Helper()
	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p[0] + "=" + p[1] + "\n")
	}
	return sb.String()
}

func TestFlatten_AddsPrefix(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFlattenTestIdentity(t)
	sealFlattenEnv(t, dir, ".env", "DB_HOST=localhost\nDB_PORT=5432\n", rec)

	v := New(dir)
	res, err := v.Flatten(filepath.Join(dir, ".env"), id, rec, FlattenOptions{Prefix: "APP", Separator: "_"})
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if res.Transformed == 0 {
		t.Error("expected transformed count > 0")
	}

	out := decryptFlattenEnv(t, encryptedPath(filepath.Join(dir, ".env")), id)
	if !strings.Contains(out, "APP_DB_HOST=localhost") {
		t.Errorf("expected APP_DB_HOST in output, got:\n%s", out)
	}
	if !strings.Contains(out, "APP_DB_PORT=5432") {
		t.Errorf("expected APP_DB_PORT in output, got:\n%s", out)
	}
}

func TestFlatten_UppercaseKeys(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFlattenTestIdentity(t)
	sealFlattenEnv(t, dir, ".env", "db_host=localhost\napi_key=secret\n", rec)

	v := New(dir)
	_, err := v.Flatten(filepath.Join(dir, ".env"), id, rec, FlattenOptions{Uppercase: true})
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}

	out := decryptFlattenEnv(t, encryptedPath(filepath.Join(dir, ".env")), id)
	if !strings.Contains(out, "DB_HOST=localhost") {
		t.Errorf("expected DB_HOST in output, got:\n%s", out)
	}
	if !strings.Contains(out, "API_KEY=secret") {
		t.Errorf("expected API_KEY in output, got:\n%s", out)
	}
}

func TestFlatten_DryRunDoesNotModify(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFlattenTestIdentity(t)
	sealFlattenEnv(t, dir, ".env", "FOO=bar\n", rec)

	encPath := encryptedPath(filepath.Join(dir, ".env"))
	origStat, err := os.Stat(encPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	v := New(dir)
	_, err = v.Flatten(filepath.Join(dir, ".env"), id, rec, FlattenOptions{Prefix: "DRY", DryRun: true})
	if err != nil {
		t.Fatalf("flatten dry run: %v", err)
	}

	newStat, err := os.Stat(encPath)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if newStat.ModTime() != origStat.ModTime() {
		t.Error("dry run should not modify the encrypted file")
	}
}

func TestFlatten_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateFlattenTestIdentity(t)

	v := New(dir)
	_, err := v.Flatten(filepath.Join(dir, ".env"), id, rec, FlattenOptions{})
	if err == nil {
		t.Error("expected error for missing encrypted file")
	}
}
