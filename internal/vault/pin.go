package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// PinEntry records a pinned vault file with an optional label.
type PinEntry struct {
	Path      string    `json:"path"`
	Label     string    `json:"label,omitempty"`
	PinnedAt  time.Time `json:"pinned_at"`
}

func pinIndexPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault", "pins.json")
}

// LoadPins returns all pinned entries for the given vault directory.
func LoadPins(vaultDir string) ([]PinEntry, error) {
	p := pinIndexPath(vaultDir)
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return []PinEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []PinEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// SavePins persists the pin list to disk.
func SavePins(vaultDir string, entries []PinEntry) error {
	p := pinIndexPath(vaultDir)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// AddPin adds or updates a pin for the given encrypted file path.
func AddPin(vaultDir, encPath, label string) error {
	entries, err := LoadPins(vaultDir)
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Path == encPath {
			entries[i].Label = label
			entries[i].PinnedAt = time.Now().UTC()
			return SavePins(vaultDir, entries)
		}
	}
	entries = append(entries, PinEntry{
		Path:     encPath,
		Label:    label,
		PinnedAt: time.Now().UTC(),
	})
	return SavePins(vaultDir, entries)
}

// RemovePin removes the pin for the given encrypted file path.
func RemovePin(vaultDir, encPath string) error {
	entries, err := LoadPins(vaultDir)
	if err != nil {
		return err
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.Path != encPath {
			filtered = append(filtered, e)
		}
	}
	return SavePins(vaultDir, filtered)
}

// IsPinned reports whether the given encrypted file path is pinned.
func IsPinned(vaultDir, encPath string) (bool, error) {
	entries, err := LoadPins(vaultDir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Path == encPath {
			return true, nil
		}
	}
	return false, nil
}
