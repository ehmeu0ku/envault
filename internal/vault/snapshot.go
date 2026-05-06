package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

type SnapshotEntry struct {
	ID      string    `json:"id"`
	File    string    `json:"file"`
	TakenAt time.Time `json:"taken_at"`
}

func snapshotDir(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault", "snapshots")
}

func snapshotIndexPath(vaultDir string) string {
	return filepath.Join(snapshotDir(vaultDir), "index.json")
}

// TakeSnapshot copies the current sealed vault file into the snapshot store.
func (v *Vault) TakeSnapshot(recipient age.Recipient) (string, error) {
	src := encryptedPath(v.dir, v.name)
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return "", fmt.Errorf("sealed vault %q not found; seal it first", v.name)
	}

	if err := os.MkdirAll(snapshotDir(v.dir), 0o700); err != nil {
		return "", fmt.Errorf("create snapshot dir: %w", err)
	}

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	dest := filepath.Join(snapshotDir(v.dir), id+".age")

	if err := copyFile(src, dest); err != nil {
		return "", fmt.Errorf("copy snapshot: %w", err)
	}

	entry := SnapshotEntry{
		ID:      id,
		File:    v.name,
		TakenAt: time.Now().UTC(),
	}
	if err := appendSnapshotIndex(v.dir, entry); err != nil {
		_ = os.Remove(dest)
		return "", err
	}

	return id, nil
}

// ListSnapshots returns all snapshots recorded for this vault file.
func (v *Vault) ListSnapshots() ([]SnapshotEntry, error) {
	idxPath := snapshotIndexPath(v.dir)
	data, err := os.ReadFile(idxPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot index: %w", err)
	}

	var all []SnapshotEntry
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("parse snapshot index: %w", err)
	}

	var filtered []SnapshotEntry
	for _, e := range all {
		if e.File == v.name {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

func appendSnapshotIndex(vaultDir string, entry SnapshotEntry) error {
	idxPath := snapshotIndexPath(vaultDir)
	var entries []SnapshotEntry

	if data, err := os.ReadFile(idxPath); err == nil {
		_ = json.Unmarshal(data, &entries)
	}

	entries = append(entries, entry)
	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot index: %w", err)
	}
	return os.WriteFile(idxPath, out, 0o600)
}
