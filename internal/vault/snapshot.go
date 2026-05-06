package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Snapshot represents a point-in-time backup of an encrypted vault file.
type Snapshot struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	SourcePath string   `json:"source_path"`
}

func snapshotDir(vaultDir string) string {
	return filepath.Join(vaultDir, ".snapshots")
}

func snapshotIndexPath(vaultDir string) string {
	return filepath.Join(snapshotDir(vaultDir), "index.json")
}

// TakeSnapshot copies the encrypted file to a timestamped snapshot.
func (v *Vault) TakeSnapshot(name string) (*Snapshot, error) {
	srcPath := encryptedPath(v.dir, name)
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot: read source %q: %w", srcPath, err)
	}

	dir := snapshotDir(v.dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("snapshot: create snapshot dir: %w", err)
	}

	timestamp := time.Now().UTC()
	snapshotFile := fmt.Sprintf("%s_%s.age", name, timestamp.Format("20060102T150405Z"))
	destPath := filepath.Join(dir, snapshotFile)

	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return nil, fmt.Errorf("snapshot: write snapshot file: %w", err)
	}

	snap := &Snapshot{
		Name:       snapshotFile,
		CreatedAt:  timestamp,
		SourcePath: srcPath,
	}

	if err := appendSnapshotIndex(v.dir, snap); err != nil {
		return nil, err
	}

	return snap, nil
}

// ListSnapshots returns all recorded snapshots for the vault directory.
func (v *Vault) ListSnapshots() ([]Snapshot, error) {
	data, err := os.ReadFile(snapshotIndexPath(v.dir))
	if os.IsNotExist(err) {
		return []Snapshot{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot: read index: %w", err)
	}
	var snaps []Snapshot
	if err := json.Unmarshal(data, &snaps); err != nil {
		return nil, fmt.Errorf("snapshot: parse index: %w", err)
	}
	return snaps, nil
}

func appendSnapshotIndex(vaultDir string, snap *Snapshot) error {
	snaps, err := (&Vault{dir: vaultDir}).ListSnapshots()
	if err != nil {
		return err
	}
	snaps = append(snaps, *snap)
	data, err := json.MarshalIndent(snaps, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot: marshal index: %w", err)
	}
	return os.WriteFile(snapshotIndexPath(vaultDir), data, 0600)
}
