package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// Rename moves an encrypted vault file from one name to another within the
// same vault directory, updating the plaintext counterpart path accordingly.
func (v *Vault) Rename(oldName, newName string) error {
	oldEnc := v.encryptedPath(oldName)
	newEnc := v.encryptedPath(newName)

	if _, err := os.Stat(oldEnc); os.IsNotExist(err) {
		return fmt.Errorf("rename: source encrypted file not found: %s", oldEnc)
	}

	if _, err := os.Stat(newEnc); err == nil {
		return fmt.Errorf("rename: destination already exists: %s", newEnc)
	}

	if err := os.MkdirAll(filepath.Dir(newEnc), 0o700); err != nil {
		return fmt.Errorf("rename: create destination directory: %w", err)
	}

	if err := os.Rename(oldEnc, newEnc); err != nil {
		return fmt.Errorf("rename: move encrypted file: %w", err)
	}

	// Best-effort removal of the old plaintext file if present.
	oldPlain := filepath.Join(v.Dir, oldName)
	_ = os.Remove(oldPlain)

	return nil
}
