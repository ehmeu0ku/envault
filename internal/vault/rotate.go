package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Rotate re-encrypts an existing sealed file with a new recipient key.
// The old encrypted file is replaced atomically.
func (v *Vault) Rotate(name string, newRecipient age.Recipient) error {
	encPath := encryptedPath(v.dir, name)

	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return fmt.Errorf("rotate: encrypted file not found: %s", encPath)
	}

	// Decrypt to a temp file using the current identity
	tmpFile, err := os.CreateTemp(v.dir, ".rotate-*")
	if err != nil {
		return fmt.Errorf("rotate: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := v.crypto.DecryptFile(encPath, tmpPath, v.identity); err != nil {
		return fmt.Errorf("rotate: decrypt with current identity: %w", err)
	}

	// Re-encrypt with the new recipient
	newEncPath := encPath + ".new"
	if err := v.crypto.EncryptFile(tmpPath, newEncPath, newRecipient); err != nil {
		os.Remove(newEncPath)
		return fmt.Errorf("rotate: encrypt with new recipient: %w", err)
	}

	// Atomically replace old encrypted file
	if err := os.Rename(newEncPath, encPath); err != nil {
		os.Remove(newEncPath)
		return fmt.Errorf("rotate: replace encrypted file: %w", err)
	}

	return nil
}

// RotateAll re-encrypts all sealed files in the vault with a new recipient key.
func (v *Vault) RotateAll(newRecipient age.Recipient) ([]string, error) {
	entries, err := v.List()
	if err != nil {
		return nil, fmt.Errorf("rotate-all: list vault: %w", err)
	}

	var rotated []string
	for _, entry := range entries {
		base := filepath.Base(entry.EncryptedPath)
		// strip .age suffix to get the original name
		name := base[:len(base)-len(".age")]
		if err := v.Rotate(name, newRecipient); err != nil {
			return rotated, fmt.Errorf("rotate-all: %w", err)
		}
		rotated = append(rotated, name)
	}
	return rotated, nil
}
