package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TTLEntry holds expiry metadata for a sealed vault file.
type TTLEntry struct {
	Path      string    `json:"path"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TTLIndex maps vault file paths to their TTL entries.
type TTLIndex map[string]TTLEntry

func ttlIndexPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".ttl_index.json")
}

// LoadTTLIndex reads the TTL index from disk, returning an empty index if missing.
func LoadTTLIndex(vaultDir string) (TTLIndex, error) {
	path := ttlIndexPath(vaultDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(TTLIndex), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ttl index: %w", err)
	}
	var idx TTLIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse ttl index: %w", err)
	}
	return idx, nil
}

// SaveTTLIndex writes the TTL index to disk.
func SaveTTLIndex(vaultDir string, idx TTLIndex) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ttl index: %w", err)
	}
	return os.WriteFile(ttlIndexPath(vaultDir), data, 0600)
}

// SetTTL assigns an expiry duration to a vault file path.
func SetTTL(vaultDir, filePath string, d time.Duration) error {
	idx, err := LoadTTLIndex(vaultDir)
	if err != nil {
		return err
	}
	idx[filePath] = TTLEntry{
		Path:      filePath,
		ExpiresAt: time.Now().Add(d),
	}
	return SaveTTLIndex(vaultDir, idx)
}

// IsExpired reports whether the given vault file has passed its TTL.
func IsExpired(vaultDir, filePath string) (bool, error) {
	idx, err := LoadTTLIndex(vaultDir)
	if err != nil {
		return false, err
	}
	entry, ok := idx[filePath]
	if !ok {
		return false, nil
	}
	return time.Now().After(entry.ExpiresAt), nil
}

// PurgeExpired removes vault files whose TTL has elapsed and cleans up the index.
func PurgeExpired(vaultDir string) ([]string, error) {
	idx, err := LoadTTLIndex(vaultDir)
	if err != nil {
		return nil, err
	}
	var purged []string
	for k, entry := range idx {
		if time.Now().After(entry.ExpiresAt) {
			_ = os.Remove(entry.Path)
			purged = append(purged, entry.Path)
			delete(idx, k)
		}
	}
	if len(purged) > 0 {
		if err := SaveTTLIndex(vaultDir, idx); err != nil {
			return purged, err
		}
	}
	return purged, nil
}
