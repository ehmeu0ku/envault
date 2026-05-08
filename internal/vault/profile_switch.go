package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// SwitchProfile decrypts the env file associated with the named profile
// and writes it to destPath (e.g. ".env") using the provided identity file.
func SwitchProfile(vaultDir, name, identityFile, destPath string) error {
	p, err := GetProfile(vaultDir, name)
	if err != nil {
		return fmt.Errorf("switch profile: %w", err)
	}

	encPath := encryptedPath(p.EnvFile)
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return fmt.Errorf("encrypted file not found for profile %q: %s", name, encPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}

	v := New(vaultDir, identityFile)
	if err := v.Unseal(encPath); err != nil {
		return fmt.Errorf("unseal profile %q: %w", name, err)
	}

	// If destPath differs from the default decrypted location, move it.
	defaultDest := p.EnvFile
	if destPath != "" && destPath != defaultDest {
		if err := os.Rename(defaultDest, destPath); err != nil {
			return fmt.Errorf("move decrypted file to %s: %w", destPath, err)
		}
	}
	return nil
}

// ActiveProfile reads a small marker file that records the last switched profile.
func ActiveProfile(vaultDir string) (string, error) {
	marker := filepath.Join(vaultDir, ".envault_active_profile")
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read active profile marker: %w", err)
	}
	return string(data), nil
}

// SetActiveProfile writes the active profile name to a marker file.
func SetActiveProfile(vaultDir, name string) error {
	marker := filepath.Join(vaultDir, ".envault_active_profile")
	return os.WriteFile(marker, []byte(name), 0600)
}
