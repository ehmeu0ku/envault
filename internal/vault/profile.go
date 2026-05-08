package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Profile represents a named environment configuration profile (e.g. dev, staging, prod).
type Profile struct {
	Name      string    `json:"name"`
	EnvFile   string    `json:"env_file"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProfileIndex maps profile names to their metadata.
type ProfileIndex map[string]Profile

func profileIndexPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault_profiles.json")
}

// LoadProfiles reads the profile index from disk. Returns empty index if missing.
func LoadProfiles(vaultDir string) (ProfileIndex, error) {
	path := profileIndexPath(vaultDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(ProfileIndex), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read profile index: %w", err)
	}
	var idx ProfileIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse profile index: %w", err)
	}
	return idx, nil
}

// SaveProfiles writes the profile index to disk.
func SaveProfiles(vaultDir string, idx ProfileIndex) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile index: %w", err)
	}
	return os.WriteFile(profileIndexPath(vaultDir), data, 0600)
}

// AddProfile registers a profile pointing to the given env file.
func AddProfile(vaultDir, name, envFile string) error {
	idx, err := LoadProfiles(vaultDir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if existing, ok := idx[name]; ok {
		existing.EnvFile = envFile
		existing.UpdatedAt = now
		idx[name] = existing
	} else {
		idx[name] = Profile{Name: name, EnvFile: envFile, CreatedAt: now, UpdatedAt: now}
	}
	return SaveProfiles(vaultDir, idx)
}

// RemoveProfile deletes a profile from the index.
func RemoveProfile(vaultDir, name string) error {
	idx, err := LoadProfiles(vaultDir)
	if err != nil {
		return err
	}
	if _, ok := idx[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(idx, name)
	return SaveProfiles(vaultDir, idx)
}

// GetProfile retrieves a single profile by name.
func GetProfile(vaultDir, name string) (Profile, error) {
	idx, err := LoadProfiles(vaultDir)
	if err != nil {
		return Profile{}, err
	}
	p, ok := idx[name]
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found", name)
	}
	return p, nil
}
