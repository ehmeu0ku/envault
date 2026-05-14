package vault

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func generateDiffReportIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealDiffEnv(t *testing.T, vaultDir, name, content string, id age.Identity) {
	t.Helper()
	v := New(vaultDir)
	plain := filepath.Join(vaultDir, name)
	if err := writeEnvFile(plain, content); err != nil {
		t.Fatalf("write env: %v", err)
	}
	recip, ok := id.(*age.X25519Identity)
	if !ok {
		t.Fatal("not X25519Identity")
	}
	if err := v.Seal(plain, recip.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func TestDiffReport_NoChanges(t *testing.T) {
	dir := t.TempDir()
	id := generateDiffReportIdentity(t)
	content := "KEY=value\nFOO=bar\n"
	sealDiffEnv(t, dir, ".env", content, id)
	sealDiffEnv(t, dir, ".env.prod", content, id)

	var buf bytes.Buffer
	err := DiffReport(dir, ".env", ".env.prod", id, DiffReportText, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No differences") {
		t.Errorf("expected no-diff message, got: %s", buf.String())
	}
}

func TestDiffReport_ShowsChanges(t *testing.T) {
	dir := t.TempDir()
	id := generateDiffReportIdentity(t)
	sealDiffEnv(t, dir, ".env", "KEY=old\nONLY_A=yes\n", id)
	sealDiffEnv(t, dir, ".env.prod", "KEY=new\nONLY_B=yes\n", id)

	var buf bytes.Buffer
	err := DiffReport(dir, ".env", ".env.prod", id, DiffReportText, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEY") {
		t.Errorf("expected KEY in output, got: %s", out)
	}
	if !strings.Contains(out, "+") {
		t.Errorf("expected added marker, got: %s", out)
	}
	if !strings.Contains(out, "-") {
		t.Errorf("expected removed marker, got: %s", out)
	}
}

func TestDiffReport_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	id := generateDiffReportIdentity(t)
	sealDiffEnv(t, dir, ".env", "KEY=one\n", id)
	sealDiffEnv(t, dir, ".env.prod", "KEY=two\n", id)

	var buf bytes.Buffer
	err := DiffReport(dir, ".env", ".env.prod", id, DiffReportJSON, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\"status\":\"changed\"") {
		t.Errorf("expected JSON changed status, got: %s", out)
	}
}

func TestDiffReport_MissingFile(t *testing.T) {
	dir := t.TempDir()
	id := generateDiffReportIdentity(t)
	sealDiffEnv(t, dir, ".env", "KEY=val\n", id)

	var buf bytes.Buffer
	err := DiffReport(dir, ".env", ".env.missing", id, DiffReportText, &buf)
	if err == nil {
		t.Error("expected error for missing file")
	}
}
