package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/user/envault/internal/crypto"
	age "filippo.io/age"
)

// Share re-encrypts a sealed vault file for one or more additional recipients,
// writing the result to destPath. The caller must supply at least one identity
// to decrypt the source and at least one recipient to encrypt for the destination.
func (v *Vault) Share(envFile string, recipients []age.Recipient, destPath string) error {
	src := encryptedPath(envFile)
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("share: sealed file not found: %s", src)
	}

	if len(recipients) == 0 {
		return fmt.Errorf("share: at least one recipient is required")
	}

	// Decrypt to a temp file using the vault's own identities.
	tmp, err := os.CreateTemp("", "envault-share-*")
	if err != nil {
		return fmt.Errorf("share: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	if err := crypto.DecryptFile(src, tmpPath, v.identities); err != nil {
		return fmt.Errorf("share: decrypt source: %w", err)
	}

	// Ensure destination directory exists.
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return fmt.Errorf("share: create dest dir: %w", err)
	}

	if err := crypto.EncryptFile(tmpPath, destPath, recipients); err != nil {
		return fmt.Errorf("share: encrypt for recipients: %w", err)
	}

	return nil
}
