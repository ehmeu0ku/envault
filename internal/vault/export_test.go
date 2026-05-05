package vault

import (
	"os"
	"strings"
	"testing"
)

func TestExport_DotEnvFormat(t *testing.T) {
	v, identity := tempVaultWithIdentity(t)
	writeEnvFile(t, v.dir, ".env", "KEY1=value1\nKEY2=value2\n")

	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	out, err := v.Export(".env", FormatDotEnv)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	_ = identity

	if !strings.Contains(out, "KEY1=value1") {
		t.Errorf("expected KEY1=value1 in output, got: %s", out)
	}
	if !strings.Contains(out, "KEY2=value2") {
		t.Errorf("expected KEY2=value2 in output, got: %s", out)
	}
}

func TestExport_ExportFormat(t *testing.T) {
	v, _ := tempVaultWithIdentity(t)
	writeEnvFile(t, v.dir, ".env", "FOO=bar\n")

	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	out, err := v.Export(".env", FormatExport)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if !strings.HasPrefix(out, "export ") {
		t.Errorf("expected export prefix, got: %s", out)
	}
	if !strings.Contains(out, "FOO=") {
		t.Errorf("expected FOO in output, got: %s", out)
	}
}

func TestExport_JSONFormat(t *testing.T) {
	v, _ := tempVaultWithIdentity(t)
	writeEnvFile(t, v.dir, ".env", "DB_HOST=localhost\nDB_PORT=5432\n")

	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	out, err := v.Export(".env", FormatJSON)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if !strings.HasPrefix(out, "{") {
		t.Errorf("expected JSON object, got: %s", out)
	}
	if !strings.Contains(out, `"DB_HOST"`) {
		t.Errorf("expected DB_HOST key in JSON, got: %s", out)
	}
}

func TestExport_MissingFile(t *testing.T) {
	v, _ := tempVaultWithIdentity(t)

	_, err := v.Export(".env", FormatDotEnv)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestExportFile_WritesOutput(t *testing.T) {
	v, _ := tempVaultWithIdentity(t)
	writeEnvFile(t, v.dir, ".env", "SECRET=abc123\n")

	if err := v.Seal(".env"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	dest := t.TempDir() + "/exported.env"
	if err := v.ExportFile(".env", FormatDotEnv, dest); err != nil {
		t.Fatalf("export file: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if !strings.Contains(string(data), "SECRET=abc123") {
		t.Errorf("expected SECRET=abc123 in exported file, got: %s", data)
	}
}

func TestFormatOutput_UnknownFormat(t *testing.T) {
	pairs := []envPair{{Key: "K", Value: "V"}}
	_, err := formatOutput(pairs, ExportFormat("xml"))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}
