package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateTemplate_CreatesTemplateFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	tmplPath := filepath.Join(dir, ".env.template")

	content := "# Database host\nDB_HOST=localhost\n# required\nDB_PASS=secret\nOPTIONAL_KEY=value\n"
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	if err := GenerateTemplate(envPath, tmplPath); err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	data, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := string(data)

	if !containsStr(tmpl, "DB_HOST=") {
		t.Error("expected DB_HOST= in template")
	}
	if !containsStr(tmpl, "DB_PASS=") {
		t.Error("expected DB_PASS= in template")
	}
	if containsStr(tmpl, "localhost") {
		t.Error("template should not contain values")
	}
	if containsStr(tmpl, "secret") {
		t.Error("template should not contain values")
	}
}

func TestGenerateTemplate_PreservesComments(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	tmplPath := filepath.Join(dir, ".env.template")

	content := "# My comment\nFOO=bar\n"
	_ = os.WriteFile(envPath, []byte(content), 0600)
	_ = GenerateTemplate(envPath, tmplPath)

	data, _ := os.ReadFile(tmplPath)
	if !containsStr(string(data), "# My comment") {
		t.Error("expected comment to be preserved in template")
	}
}

func TestValidateAgainstTemplate_AllPresent(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, ".env.template")
	envPath := filepath.Join(dir, ".env")

	_ = os.WriteFile(tmplPath, []byte("DB_HOST= # required\nDB_PASS= # required\n"), 0600)
	_ = os.WriteFile(envPath, []byte("DB_HOST=localhost\nDB_PASS=secret\n"), 0600)

	missing, err := ValidateAgainstTemplate(tmplPath, envPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing keys, got: %v", missing)
	}
}

func TestValidateAgainstTemplate_MissingRequired(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, ".env.template")
	envPath := filepath.Join(dir, ".env")

	_ = os.WriteFile(tmplPath, []byte("DB_HOST= # required\nDB_PASS= # required\nOPTIONAL=\n"), 0600)
	_ = os.WriteFile(envPath, []byte("DB_HOST=localhost\n"), 0600)

	missing, err := ValidateAgainstTemplate(tmplPath, envPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(missing) != 1 || missing[0] != "DB_PASS" {
		t.Errorf("expected [DB_PASS] missing, got: %v", missing)
	}
}

func TestValidateAgainstTemplate_MissingEnvFile(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, ".env.template")
	_ = os.WriteFile(tmplPath, []byte("KEY= # required\n"), 0600)

	_, err := ValidateAgainstTemplate(tmplPath, filepath.Join(dir, "nonexistent.env"))
	if err == nil {
		t.Error("expected error for missing env file")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper2(s, sub))
}

func containsHelper2(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
