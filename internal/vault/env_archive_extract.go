package vault

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractResult summarises an extract operation.
type ExtractResult struct {
	Manifest ArchiveManifest
	Extracted int
}

// Extract unpacks a zip archive previously created by Archive into destDir.
// It returns the embedded manifest and a count of extracted .age files.
func Extract(archivePath, destDir string) (*ExtractResult, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract: open archive: %w", err)
	}
	defer r.Close()

	var manifest ArchiveManifest
	var ageFiles []*zip.File

	for _, f := range r.File {
		if f.Name == "manifest.json" {
			if err := readManifest(f, &manifest); err != nil {
				return nil, fmt.Errorf("extract: read manifest: %w", err)
			}
			continue
		}
		if filepath.Ext(f.Name) == ".age" {
			ageFiles = append(ageFiles, f)
		}
	}

	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, fmt.Errorf("extract: create dest dir: %w", err)
	}

	for _, f := range ageFiles {
		if err := extractFile(f, destDir); err != nil {
			return nil, fmt.Errorf("extract: %s: %w", f.Name, err)
		}
	}

	return &ExtractResult{Manifest: manifest, Extracted: len(ageFiles)}, nil
}

func readManifest(f *zip.File, m *ArchiveManifest) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return json.NewDecoder(rc).Decode(m)
}

func extractFile(f *zip.File, destDir string) error {
	// Prevent zip-slip
	dest := filepath.Join(destDir, filepath.Clean("/"+f.Name))
	if !strings.HasPrefix(dest, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", f.Name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(out, rc)
	return err
}
