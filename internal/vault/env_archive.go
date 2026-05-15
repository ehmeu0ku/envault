package vault

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ArchiveManifest describes the contents of an archive.
type ArchiveManifest struct {
	CreatedAt time.Time         `json:"created_at"`
	VaultDir  string            `json:"vault_dir"`
	Files     []ArchiveEntry    `json:"files"`
}

// ArchiveEntry is a single encrypted file recorded in the manifest.
type ArchiveEntry struct {
	RelPath   string    `json:"rel_path"`
	ArchivedAt time.Time `json:"archived_at"`
}

// Archive bundles all .age files in vaultDir into a zip archive at destPath.
// A manifest.json is embedded at the root of the zip.
func Archive(vaultDir, destPath string) (int, error) {
	entries, err := collectAgeFiles(vaultDir)
	if err != nil {
		return 0, fmt.Errorf("archive: collect files: %w", err)
	}
	if len(entries) == 0 {
		return 0, fmt.Errorf("archive: no encrypted files found in %s", vaultDir)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return 0, fmt.Errorf("archive: create dest dir: %w", err)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return 0, fmt.Errorf("archive: create zip: %w", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	var manifestEntries []ArchiveEntry
	now := time.Now().UTC()

	for _, rel := range entries {
		abs := filepath.Join(vaultDir, rel)
		if err := addFileToZip(zw, abs, rel); err != nil {
			return 0, fmt.Errorf("archive: add %s: %w", rel, err)
		}
		manifestEntries = append(manifestEntries, ArchiveEntry{RelPath: rel, ArchivedAt: now})
	}

	manifest := ArchiveManifest{
		CreatedAt: now,
		VaultDir:  vaultDir,
		Files:     manifestEntries,
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("archive: marshal manifest: %w", err)
	}
	mw, err := zw.Create("manifest.json")
	if err != nil {
		return 0, fmt.Errorf("archive: create manifest entry: %w", err)
	}
	if _, err := mw.Write(mb); err != nil {
		return 0, fmt.Errorf("archive: write manifest: %w", err)
	}

	return len(manifestEntries), nil
}

func collectAgeFiles(dir string) ([]string, error) {
	var rel []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".age" {
			r, _ := filepath.Rel(dir, path)
			rel = append(rel, r)
		}
		return nil
	})
	return rel, err
}

func addFileToZip(zw *zip.Writer, absPath, relPath string) error {
	src, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer src.Close()
	w, err := zw.Create(relPath)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}
