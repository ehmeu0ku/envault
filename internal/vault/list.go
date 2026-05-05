package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Entry represents a sealed vault entry found on disk.
type Entry struct {
	Name      string // base name without .age suffix
	Path      string // full path to the .age file
	PlainPath string // expected path of the decrypted file
}

// List returns all sealed (.age) entries found in dir.
func (v *Vault) List(dir string) ([]Entry, error) {
	pattern := filepath.Join(dir, "*.age")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", pattern, err)
	}

	entries := make([]Entry, 0, len(matches))
	for _, p := range matches {
		base := filepath.Base(p)
		name := strings.TrimSuffix(base, ".age")
		entries = append(entries, Entry{
			Name:      name,
			Path:      p,
			PlainPath: filepath.Join(dir, name),
		})
	}
	return entries, nil
}

// Status reports whether the plaintext counterpart of a sealed entry exists.
func (e *Entry) Status() string {
	if _, err := os.Stat(e.PlainPath); err == nil {
		return "unsealed"
	}
	return "sealed"
}
