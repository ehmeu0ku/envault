package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generatePivotTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealPivotEnv(t *testing.T, dir, name, content string, rec age.Recipient) string {
	t.Helper()
	plain := filepath.Join(dir, name)
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	v := New(dir)
	if err := v.Seal(plain, []age.Recipient{rec}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	os.Remove(plain)
	return encryptedPath(plain)
}

func decryptPivotEnv(t *testing.T, path string, id age.Identity) string {
	t.Helper()
	data, err := DecryptFile(path, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(data)
}

func TestPivot_RenamesPrefix(t *testing.T) {
	dir := t.TempDir()
	id, rec := generatePivotTestIdentity(t)

	content := "DEV_HOST=localhost\nDEV_PORT=5432\nAPP_NAME=myapp\n"
	sealPivotEnv(t, dir, ".env", content, rec)

	v := New(dir)
	res, err := v.Pivot(".env", []age.Recipient{rec}, id, PivotOptions{
		OldPrefix:  "DEV_",
		NewPrefix:  "PROD_",
		FailIfNone: true,
	})
	if err != nil {
		t.Fatalf("pivot: %v", err)
	}
	if res.Renamed != 2 {
		t.Errorf("renamed = %d, want 2", res.Renamed)
	}
	if res.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", res.Unchanged)
	}

	out := decryptPivotEnv(t, filepath.Join(dir, encryptedPath(".env")), id)
	if !strings.Contains(out, "PROD_HOST=localhost") {
		t.Errorf("expected PROD_HOST in output, got:\n%s", out)
	}
	if strings.Contains(out, "DEV_HOST") {
		t.Errorf("old key DEV_HOST should not appear in output")
	}
}

func TestPivot_FailIfNone(t *testing.T) {
	dir := t.TempDir()
	id, rec := generatePivotTestIdentity(t)

	content := "APP_KEY=secret\n"
	sealPivotEnv(t, dir, ".env", content, rec)

	v := New(dir)
	_, err := v.Pivot(".env", []age.Recipient{rec}, id, PivotOptions{
		OldPrefix:  "MISSING_",
		NewPrefix:  "NEW_",
		FailIfNone: true,
	})
	if err == nil {
		t.Fatal("expected error when no keys matched, got nil")
	}
}

func TestPivot_MissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	id, rec := generatePivotTestIdentity(t)

	v := New(dir)
	_, err := v.Pivot("nonexistent.env", []age.Recipient{rec}, id, PivotOptions{
		OldPrefix: "X_",
		NewPrefix: "Y_",
	})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestPivot_EmptyPrefixRenamesNothing(t *testing.T) {
	dir := t.TempDir()
	id, rec := generatePivotTestIdentity(t)

	content := "FOO=bar\nBAZ=qux\n"
	sealPivotEnv(t, dir, ".env", content, rec)

	v := New(dir)
	res, err := v.Pivot(".env", []age.Recipient{rec}, id, PivotOptions{})
	if err != nil {
		t.Fatalf("pivot: %v", err)
	}
	if res.Renamed != 0 {
		t.Errorf("expected 0 renamed, got %d", res.Renamed)
	}
	if res.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", res.Unchanged)
	}
}
