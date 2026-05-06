package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Copy re-encrypts a sealed .env.age file from the current vault directory
// to a destination directory, encrypting for the provided recipient.
func (v *Vault) Copy(filename, destDir string, recipient age.Recipient) error {
	src := encryptedPath(filepath.Join(v.dir, filename))
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("copy: sealed file not found: %s", src)
	}

	// Decrypt with current vault identity.
	tmpFile, err := os.CreateTemp("", "envault-copy-*.env")
	if err != nil {
		return fmt.Errorf("copy: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := v.crypto.DecryptFile(src, tmpPath, v.identity); err != nil {
		return fmt.Errorf("copy: decrypt source: %w", err)
	}

	// Ensure destination directory exists.
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("copy: create dest dir: %w", err)
	}

	destFile := encryptedPath(filepath.Join(destDir, filename))
	if err := v.crypto.EncryptFile(tmpPath, destFile, recipient); err != nil {
		return fmt.Errorf("copy: encrypt to destination: %w", err)
	}

	return nil
}
