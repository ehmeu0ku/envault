package vault_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envault/internal/vault"
)

func TestArchive_CreatesZipWithAgeFiles(t *testing.T) {
	vaultDir := t.TempDir()
	destDir := t.TempDir()

	// Write two fake .age files
	for _, name := range []string{"prod.env.age", "staging.env.age"} {
		if err := os.WriteFile(filepath.Join(vaultDir, name), []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	destPath := filepath.Join(destDir, "vault.zip")
	n, err := vault.Archive(vaultDir, destPath)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 files archived, got %d", n)
	}

	r, err := zip.OpenReader(destPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	names := map[string]bool{}
	for _, f := range r.File {
		names[f.Name] = true
	}
	if !names["manifest.json"] {
		t.Error("manifest.json not found in archive")
	}
	if !names["prod.env.age"] || !names["staging.env.age"] {
		t.Error("expected both .age files in archive")
	}
}

func TestArchive_EmptyVaultReturnsError(t *testing.T) {
	vaultDir := t.TempDir()
	destPath := filepath.Join(t.TempDir(), "vault.zip")
	_, err := vault.Archive(vaultDir, destPath)
	if err == nil {
		t.Fatal("expected error for empty vault, got nil")
	}
}

func TestExtract_RestoresFiles(t *testing.T) {
	vaultDir := t.TempDir()
	archiveDir := t.TempDir()
	extractDir := t.TempDir()

	origContent := []byte("age-encrypted-bytes")
	if err := os.WriteFile(filepath.Join(vaultDir, "prod.env.age"), origContent, 0o600); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(archiveDir, "vault.zip")
	if _, err := vault.Archive(vaultDir, destPath); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	result, err := vault.Extract(destPath, extractDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result.Extracted != 1 {
		t.Fatalf("expected 1 extracted, got %d", result.Extracted)
	}

	got, err := os.ReadFile(filepath.Join(extractDir, "prod.env.age"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != string(origContent) {
		t.Errorf("content mismatch: got %q, want %q", got, origContent)
	}
}

func TestExtract_MissingArchiveReturnsError(t *testing.T) {
	_, err := vault.Extract("/nonexistent/vault.zip", t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing archive")
	}
}

func TestExtract_ManifestContainsMetadata(t *testing.T) {
	vaultDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(vaultDir, "dev.env.age"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(t.TempDir(), "vault.zip")
	if _, err := vault.Archive(vaultDir, destPath); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Extract(destPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.CreatedAt.IsZero() {
		t.Error("manifest CreatedAt should not be zero")
	}
	if len(result.Manifest.Files) != 1 {
		t.Errorf("expected 1 manifest entry, got %d", len(result.Manifest.Files))
	}
}
